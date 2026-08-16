//! Executable coefficient-to-view maps for the selected compact proof.
//!
//! Every linear or affine verifier view is derived from the decoded proof
//! contract. Nonlinear salted-Merkle and frontier programming belongs to its
//! own proof owner; this module exports only the internal-commitment embedding
//! that connects those commitments to outer response components.

use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};

use super::compact_cfw::CompactChallengeField;
use super::compact_cfw_geometry::COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER;
use super::compact_cfw_geometry::{
    COMPACT_CFW_MATRIX_COUNT, COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH,
};
use super::compact_proof_contract::{
    CompactPublicKeyVerifierInputs, CompactResponseComponentRoleContract,
    CompactWhirMaskGroupContract, selected_compact_public_key_proof_contract,
};
use super::compact_response_merkle::{
    CompactResponseLeafValueKind, CompactResponseMerkleGeometry, CompactResponseQuerySelection,
};

const WHIR_SUMCHECK_MASK_MESSAGE_LENGTH: u64 = 3;
const WHIR_FOLD_COUNT_PER_EPOCH: usize = 4;

/// Closed semantic census consumed by the masking-premise gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub(crate) enum CompactMaskingViewRole {
    Source = 1,
    CarriedMask = 2,
    Mirror = 3,
    CodeSwitch = 4,
    Fold = 5,
    Quotient = 6,
    Sumcheck = 7,
    ExplicitPoint = 8,
    Terminal = 9,
}

pub(crate) const COMPACT_MASKING_VIEW_ROLES: [CompactMaskingViewRole; 9] = [
    CompactMaskingViewRole::Source,
    CompactMaskingViewRole::CarriedMask,
    CompactMaskingViewRole::Mirror,
    CompactMaskingViewRole::CodeSwitch,
    CompactMaskingViewRole::Fold,
    CompactMaskingViewRole::Quotient,
    CompactMaskingViewRole::Sumcheck,
    CompactMaskingViewRole::ExplicitPoint,
    CompactMaskingViewRole::Terminal,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactMaskingMapCoordinate {
    pub(crate) role: CompactMaskingViewRole,
    pub(crate) epoch: u8,
    pub(crate) batch_ordinal: u8,
    pub(crate) coordinate: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactSurjectivityWitness {
    /// Distinct query points expose a generalized Vandermonde minor wholly
    /// inside the independently sampled randomness suffix.
    ReedSolomonRandomnessMinor {
        randomness_length: u64,
        maximum_query_count: u64,
    },
    CoordinateIdentity,
    /// Multilinear equality weights sum to one, so at least one limb weight
    /// supplies a pivot for every folded output coordinate.
    MultilinearEqualityPartitionOfUnity {
        limb_count: u64,
    },
    /// The nonconstant round coefficients and outer evaluations expose one
    /// pivot for every independent compact-CFW outer coefficient.
    CfwOuterFullColumnRank {
        round_count: u64,
    },
    /// The fixed `[mu_tilde, c0, c2]` rows contain the production
    /// `2 * round_count + 1` constant minor for three-coefficient masks.
    WhirSumcheckConstantMinor {
        round_count: u64,
    },
    /// Each matrix role owns disjoint final-mask columns and one allowed final
    /// challenge supplies a pivot for that role's terminal value.
    CfwTerminalDisjointRolePivots {
        matrix_count: u64,
    },
    /// The disclosure rows have two independent mask-coordinate pivots:
    /// `(pre, main, pre-main)`.
    CrossEpochTwoMaskCorrection,
    /// Fresh coordinates are independent and form a unit block in the affine
    /// mirror projection.
    FreshCoordinateIdentity {
        coordinate_count: u64,
    },
    /// The derived view is an explicit projection of an earlier checked map.
    InheritedCheckedMap {
        map_ordinal: usize,
    },
    /// The scalar base claim is a nonzero runtime covector over fresh
    /// coordinates supplied by checked affine-mirror maps.
    InheritedFreshCoordinateCovector {
        dependency_count: u64,
    },
}

/// One fresh-coordinate block consumed by the base-case scalar claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactBaseCaseClaimDependency {
    pub(crate) mirror_map_ordinal: usize,
    pub(crate) lane_count: u64,
    pub(crate) message_length_per_lane: u64,
    pub(crate) randomness_length_per_lane: u64,
}

/// One executable linear or affine projection family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompactCoefficientProjection {
    /// One query of every lane in a folded Reed-Solomon source oracle.
    FoldedReedSolomonSource {
        lane_count: u64,
        message_length_per_lane: u64,
        randomness_length_per_lane: u64,
        domain_size: u64,
        maximum_query_count: u64,
    },
    /// One query of every lane in a committed carried-mask group.
    CarriedMaskReedSolomon {
        lane_count: u64,
        message_length_per_lane: u64,
        randomness_length_per_lane: u64,
        domain_size: u64,
        maximum_query_count: u64,
        contract_role_tag: u8,
    },
    /// `fresh + challenge * carried`, coordinate by coordinate.
    AffineMirror {
        carried_map_ordinal: usize,
        hidden_private_coordinate_count: u64,
        coordinate_count: u64,
    },
    /// The selected code switch has no OOD pad, so its message is exactly the
    /// current folded source randomness.
    FoldedRandomnessSuffix {
        fold_map_ordinal: usize,
        first_coordinate: u64,
        coordinate_count: u64,
    },
    /// Limb-major multilinear folding by the equality table at the sampled
    /// fold point.
    LimbFold {
        input_limb_count: u64,
        output_message_length: u64,
        output_randomness_length: u64,
    },
    /// The pre-challenge quotient source copies this authenticated main-source
    /// prefix; the rest of the pre-challenge source is fixed zero padding.
    QuotientPrefix {
        copied_element_count: u64,
        pre_challenge_element_count: u64,
        main_element_count: u64,
    },
    /// Complete WHIR masked-sumcheck transcript: `mu_tilde`, followed by every
    /// round wire polynomial with the reconstructible linear term omitted.
    WhirSumcheckTranscript {
        round_count: u64,
        mask_message_length: u64,
    },
    /// Complete compact-CFW outer-mask transcript contribution.
    CfwOuterTranscript { round_count: u64 },
    /// The three cross-epoch disclosures as a projection of the copied source
    /// prefix and the two shared-mask coordinates.
    CrossEpochExplicitPoint {
        copied_element_count: u64,
        point_coordinate_count: u32,
    },
    /// The three compact-CFW terminal masked values from every independent
    /// inner-mask coefficient.
    CfwInnerTerminal { round_count: u64, matrix_count: u64 },
    /// Fresh-side base-case claim before the blinding challenge is sampled.
    WhirBaseCaseClaim {
        dependencies: Vec<CompactBaseCaseClaimDependency>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCoefficientToViewMap {
    pub(crate) coordinate: CompactMaskingMapCoordinate,
    pub(crate) private_coordinate_count: u64,
    pub(crate) view_coordinate_count: u64,
    pub(crate) projection: CompactCoefficientProjection,
    pub(crate) surjectivity: CompactSurjectivityWitness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactMaskingCoefficientMapCertificate {
    contract_source_hash: [u8; 64],
    maps: Vec<CompactCoefficientToViewMap>,
    response_component_embeddings: Vec<CompactResponseComponentEmbedding>,
    construction_commitment_embeddings: Vec<CompactConstructionCommitmentEmbedding>,
}

/// One canonical response component's transport correspondence. This is not
/// an entropy map: it records where an already-defined verifier view is
/// embedded in the outer salted response tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactResponseComponentEmbedding {
    pub(crate) outer_response_ordinal: u32,
    pub(crate) component_ordinal: u32,
    pub(crate) semantic_role: Option<CompactMaskingViewRole>,
    pub(crate) component_role: CompactResponseComponentRoleContract,
    pub(crate) first_leaf_ordinal: u64,
    pub(crate) leaf_count: u64,
    pub(crate) minimum_queried_leaf_count: u64,
    pub(crate) maximum_queried_leaf_count: u64,
    pub(crate) query_selection: CompactResponseQuerySelection,
    pub(crate) value_kind: CompactResponseLeafValueKind,
    pub(crate) field_element_count_per_leaf: u64,
}

/// One construction commitment's unique embedding in the outer response
/// sequence. The component role retains the contract's epoch/batch/round
/// coordinate; `semantic_role` is the closed masking-view classification.
/// The shared cross-epoch mask is one owned root with two query consumers,
/// never two independently programmable commitments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactConstructionCommitmentEmbedding {
    pub(crate) commitment_ordinal: u32,
    pub(crate) outer_response_ordinal: u32,
    pub(crate) component_ordinal: u32,
    pub(crate) semantic_role: CompactMaskingViewRole,
    pub(crate) component_role: CompactResponseComponentRoleContract,
    pub(crate) ownership: CompactConstructionCommitmentOwnership,
    pub(crate) query_source: CompactCommitmentQuerySource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactConstructionCommitmentOwnership {
    OwnedByEpoch { epoch: u8 },
    OwnedByPreChallengeEpochReusedByMainEpoch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactCommitmentQueryCoordinate {
    pub(crate) logical_verifier_move_ordinal: u32,
    pub(crate) distinct_query_group_ordinal: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactCommitmentQuerySource {
    Component,
    SharedCrossEpochUnion {
        owned_pre_challenge: CompactCommitmentQueryCoordinate,
        reused_main: CompactCommitmentQueryCoordinate,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactMaskingCoefficientMapError {
    ArithmeticOverflow,
    InvalidContract,
    InvalidProjection,
    MissingSemanticRole,
    InvalidConditionalImage,
    WrongConditionalImageRequest,
}

/// Runtime coordinates that specialize one certified projection without
/// letting the caller supply output rows or a claimed image basis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactConditionalImageRuntime<'a> {
    ReedSolomonQueries {
        preceding_query_positions: &'a [u64],
        query_positions: &'a [u64],
    },
    /// Deterministic spot checks of an already disclosed affine mirror. The
    /// authority supplies the retained mirror coefficients, never the query
    /// outputs; the certificate applies the exact inherited code itself.
    AffineMirrorQueries {
        query_positions: &'a [u64],
        retained_mirror_coefficients: &'a [CompactChallengeField],
    },
    WhirSumcheck {
        round_challenges: &'a [CompactChallengeField],
    },
    CfwOuter {
        round_challenges: &'a [CompactChallengeField],
    },
    CrossEpochExplicitPoint,
    CfwInnerTerminal {
        round_challenges: &'a [CompactChallengeField],
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CompactConditionalImageExpansion {
    Dense {
        offset: Vec<CompactChallengeField>,
        basis: Vec<Vec<CompactChallengeField>>,
        pivot_output_coordinates: Vec<u64>,
    },
    CoordinateInjection {
        offset: Vec<CompactChallengeField>,
        independent_output_coordinates: Vec<u64>,
    },
}

impl CompactConditionalImageExpansion {
    fn independent_coordinates(
        &self,
        output: &[CompactChallengeField],
    ) -> Vec<CompactChallengeField> {
        let coordinates = match self {
            Self::Dense {
                pivot_output_coordinates,
                ..
            } => pivot_output_coordinates,
            Self::CoordinateInjection {
                independent_output_coordinates,
                ..
            } => independent_output_coordinates,
        };
        coordinates
            .iter()
            .map(|pivot| output[*pivot as usize])
            .collect()
    }
}

/// Opaque, certificate-minted affine-image request for one transcript step.
///
/// The retained prefix values are consumed while this request is minted and
/// are not exposed through the request. It contains only the resulting
/// canonical affine coset and its exact right-inverse coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactConditionalImageRequest {
    certificate_digest: [u8; 64],
    map_ordinal: usize,
    map_coordinate: CompactMaskingMapCoordinate,
    step_ordinal: u32,
    first_output_coordinate: u64,
    output_coordinate_count: u64,
    independent_coordinate_count: u64,
    transcript_prefix_binding: [u8; 64],
    expansion: CompactConditionalImageExpansion,
}

impl CompactConditionalImageRequest {
    #[cfg(test)]
    pub(crate) const fn output_coordinate_count(&self) -> u64 {
        self.output_coordinate_count
    }

    #[cfg(test)]
    pub(crate) const fn independent_coordinate_count(&self) -> u64 {
        self.independent_coordinate_count
    }
}

impl CompactMaskingCoefficientMapCertificate {
    /// Binding for the generated contract bytes from which every map row is
    /// deterministically recomputed.
    pub(crate) const fn certificate_digest(&self) -> [u8; 64] {
        self.contract_source_hash
    }

    pub(crate) fn maps(&self) -> &[CompactCoefficientToViewMap] {
        &self.maps
    }

    pub(crate) fn response_component_embeddings(&self) -> &[CompactResponseComponentEmbedding] {
        &self.response_component_embeddings
    }

    pub(crate) fn construction_commitment_embeddings(
        &self,
    ) -> &[CompactConstructionCommitmentEmbedding] {
        &self.construction_commitment_embeddings
    }

    pub(crate) fn covered_roles(&self) -> [bool; COMPACT_MASKING_VIEW_ROLES.len()] {
        let mut covered = [false; COMPACT_MASKING_VIEW_ROLES.len()];
        for map in &self.maps {
            covered[usize::from(map.coordinate.role as u8 - 1)] = true;
        }
        covered
    }

    pub(crate) fn check(&self) -> Result<(), CompactMaskingCoefficientMapError> {
        if self.maps.is_empty()
            || self.response_component_embeddings.is_empty()
            || self.construction_commitment_embeddings.is_empty()
            || self.covered_roles().contains(&false)
        {
            return Err(CompactMaskingCoefficientMapError::MissingSemanticRole);
        }
        for (map_ordinal, map) in self.maps.iter().enumerate() {
            if map.private_coordinate_count == 0 || map.view_coordinate_count == 0 {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
            if let CompactSurjectivityWitness::InheritedCheckedMap {
                map_ordinal: source_map_ordinal,
            } = map.surjectivity
                && (source_map_ordinal >= map_ordinal
                    || self.maps.get(source_map_ordinal).is_none())
            {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
            if let CompactCoefficientProjection::WhirBaseCaseClaim { dependencies } =
                &map.projection
                && dependencies
                    .iter()
                    .any(|dependency| dependency.mirror_map_ordinal >= map_ordinal)
            {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
            check_projection(map, &self.maps)?;
            check_surjectivity_witness(map)?;
        }
        let mut expected_response_ordinal = 0_u32;
        let mut expected_component_ordinal = 0_u32;
        let mut expected_first_leaf_ordinal = 0_u64;
        for (embedding_index, embedding) in self.response_component_embeddings.iter().enumerate() {
            if embedding.outer_response_ordinal != expected_response_ordinal
                || embedding.component_ordinal != expected_component_ordinal
                || embedding.first_leaf_ordinal != expected_first_leaf_ordinal
                || embedding.leaf_count == 0
                || embedding.minimum_queried_leaf_count > embedding.maximum_queried_leaf_count
                || embedding.maximum_queried_leaf_count > embedding.leaf_count
                || (embedding.value_kind == CompactResponseLeafValueKind::Padding
                    && embedding.field_element_count_per_leaf != 0)
                || (embedding.value_kind != CompactResponseLeafValueKind::Padding
                    && embedding.field_element_count_per_leaf == 0)
            {
                return Err(CompactMaskingCoefficientMapError::InvalidContract);
            }
            expected_first_leaf_ordinal = expected_first_leaf_ordinal
                .checked_add(embedding.leaf_count)
                .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
            let next = self.response_component_embeddings.get(embedding_index + 1);
            if next.is_some_and(|next| next.outer_response_ordinal == expected_response_ordinal) {
                expected_component_ordinal = expected_component_ordinal
                    .checked_add(1)
                    .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
            } else {
                expected_response_ordinal = expected_response_ordinal
                    .checked_add(1)
                    .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
                expected_component_ordinal = 0;
                expected_first_leaf_ordinal = 0;
            }
        }
        let response_count = self
            .response_component_embeddings
            .last()
            .and_then(|embedding| embedding.outer_response_ordinal.checked_add(1))
            .ok_or(CompactMaskingCoefficientMapError::InvalidContract)?;
        if expected_response_ordinal != response_count {
            return Err(CompactMaskingCoefficientMapError::InvalidContract);
        }
        for (expected_ordinal, commitment) in
            self.construction_commitment_embeddings.iter().enumerate()
        {
            if usize::try_from(commitment.commitment_ordinal).ok() != Some(expected_ordinal) {
                return Err(CompactMaskingCoefficientMapError::InvalidContract);
            }
            let component = self
                .response_component_embeddings
                .iter()
                .find(|component| {
                    component.outer_response_ordinal == commitment.outer_response_ordinal
                        && component.component_ordinal == commitment.component_ordinal
                })
                .ok_or(CompactMaskingCoefficientMapError::InvalidContract)?;
            if component.component_role != commitment.component_role
                || component.semantic_role != Some(commitment.semantic_role)
                || !commitment_ownership_matches_component(
                    commitment.ownership,
                    commitment.component_role,
                )
                || !commitment_query_source_matches_component(
                    commitment.query_source,
                    component.query_selection,
                )
            {
                return Err(CompactMaskingCoefficientMapError::InvalidContract);
            }
            if self.construction_commitment_embeddings[..expected_ordinal]
                .iter()
                .any(|preceding| {
                    preceding.outer_response_ordinal == commitment.outer_response_ordinal
                        && preceding.component_ordinal == commitment.component_ordinal
                })
            {
                return Err(CompactMaskingCoefficientMapError::InvalidContract);
            }
        }
        let external_mask_commitment_count = self
            .construction_commitment_embeddings
            .iter()
            .filter(|commitment| matches!(commitment.component_role.role_tag, 2 | 4 | 5))
            .count();
        let shared_cross_epoch_commitment_count = self
            .construction_commitment_embeddings
            .iter()
            .filter(|commitment| {
                matches!(
                    commitment.ownership,
                    CompactConstructionCommitmentOwnership::OwnedByPreChallengeEpochReusedByMainEpoch
                )
            })
            .count();
        if self.construction_commitment_embeddings.len() != 45
            || external_mask_commitment_count != 3
            || self.construction_commitment_embeddings.len() - external_mask_commitment_count != 42
            || shared_cross_epoch_commitment_count != 1
        {
            return Err(CompactMaskingCoefficientMapError::InvalidContract);
        }
        Ok(())
    }

    /// Validates the exact runtime projection and mints its conditional image.
    ///
    /// `preceding_output_values` must be the retained, authenticated output
    /// prefix for this same map. Dense constrained families solve that prefix
    /// against the certified coefficient map and derive the next affine coset;
    /// no caller-provided output row or basis is accepted.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_conditional_image(
        &self,
        map_ordinal: usize,
        step_ordinal: u32,
        first_output_coordinate: u64,
        output_coordinate_count: u64,
        independent_coordinate_count: u64,
        transcript_prefix_binding: [u8; 64],
        preceding_output_values: &[CompactChallengeField],
        runtime: CompactConditionalImageRuntime<'_>,
    ) -> Result<CompactConditionalImageRequest, CompactMaskingCoefficientMapError> {
        let map = self
            .maps
            .get(map_ordinal)
            .ok_or(CompactMaskingCoefficientMapError::InvalidConditionalImage)?;
        let expansion = prepare_projection_conditional_image(ProjectionConditionalImageInput {
            maps: &self.maps,
            map_ordinal,
            map,
            first_output_coordinate,
            output_coordinate_count,
            independent_coordinate_count,
            preceding_output_values,
            runtime,
        })?;
        validate_conditional_expansion(
            output_coordinate_count,
            independent_coordinate_count,
            &expansion,
        )?;
        Ok(CompactConditionalImageRequest {
            certificate_digest: self.contract_source_hash,
            map_ordinal,
            map_coordinate: map.coordinate,
            step_ordinal,
            first_output_coordinate,
            output_coordinate_count,
            independent_coordinate_count,
            transcript_prefix_binding,
            expansion,
        })
    }

    /// Expands exactly `conditional_rank` independent extension-field
    /// coordinates into the certified affine image for the bound transcript
    /// step. The expected step and prefix binding make request replay across a
    /// different adaptive transcript fail closed.
    pub(crate) fn execute_conditional_image(
        &self,
        request: &CompactConditionalImageRequest,
        expected_step_ordinal: u32,
        expected_transcript_prefix_binding: [u8; 64],
        independent_coordinates: &[CompactChallengeField],
    ) -> Result<Vec<CompactChallengeField>, CompactMaskingCoefficientMapError> {
        let map = self
            .maps
            .get(request.map_ordinal)
            .ok_or(CompactMaskingCoefficientMapError::WrongConditionalImageRequest)?;
        if request.certificate_digest != self.contract_source_hash
            || request.map_coordinate != map.coordinate
            || request.step_ordinal != expected_step_ordinal
            || request.transcript_prefix_binding != expected_transcript_prefix_binding
            || u64::try_from(independent_coordinates.len()).ok()
                != Some(request.independent_coordinate_count)
            || request
                .first_output_coordinate
                .checked_add(request.output_coordinate_count)
                .is_none()
        {
            return Err(CompactMaskingCoefficientMapError::WrongConditionalImageRequest);
        }
        validate_conditional_expansion(
            request.output_coordinate_count,
            request.independent_coordinate_count,
            &request.expansion,
        )?;
        let output = match &request.expansion {
            CompactConditionalImageExpansion::Dense { offset, basis, .. } => {
                let mut output = offset.clone();
                for (coordinate, basis_vector) in independent_coordinates.iter().copied().zip(basis)
                {
                    for (destination, basis_value) in output.iter_mut().zip(basis_vector) {
                        *destination += coordinate * *basis_value;
                    }
                }
                output
            }
            CompactConditionalImageExpansion::CoordinateInjection {
                offset,
                independent_output_coordinates,
            } => {
                let mut output = offset.clone();
                for (coordinate, output_coordinate) in independent_coordinates
                    .iter()
                    .copied()
                    .zip(independent_output_coordinates)
                {
                    output[usize::try_from(*output_coordinate)
                        .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?] =
                        coordinate;
                }
                output
            }
        };
        Ok(output)
    }

    /// Reconstructs the independently parameterized affine image from the
    /// candidate's canonical pivot coordinates and refuses a value outside
    /// that image. The caller never supplies a claimed basis or rank.
    pub(crate) fn verify_conditional_image_output(
        &self,
        request: &CompactConditionalImageRequest,
        expected_step_ordinal: u32,
        expected_transcript_prefix_binding: [u8; 64],
        candidate_output: &[CompactChallengeField],
    ) -> Result<(), CompactMaskingCoefficientMapError> {
        if u64::try_from(candidate_output.len()).ok() != Some(request.output_coordinate_count) {
            return Err(CompactMaskingCoefficientMapError::WrongConditionalImageRequest);
        }
        let independent_coordinates = request.expansion.independent_coordinates(candidate_output);
        let reconstructed = self.execute_conditional_image(
            request,
            expected_step_ordinal,
            expected_transcript_prefix_binding,
            &independent_coordinates,
        )?;
        if reconstructed != candidate_output {
            return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
        }
        Ok(())
    }
}

pub(crate) fn derive_selected_compact_masking_coefficient_map_certificate()
-> Result<CompactMaskingCoefficientMapCertificate, CompactMaskingCoefficientMapError> {
    let contract = selected_compact_public_key_proof_contract()
        .map_err(|_| CompactMaskingCoefficientMapError::InvalidContract)?;
    derive_compact_masking_coefficient_map_certificate(contract.verifier_inputs())
}

pub(crate) fn derive_compact_masking_coefficient_map_certificate(
    inputs: CompactPublicKeyVerifierInputs<'_>,
) -> Result<CompactMaskingCoefficientMapCertificate, CompactMaskingCoefficientMapError> {
    let contract_source_hash = inputs
        .canonical_source_hash()
        .map_err(|_| CompactMaskingCoefficientMapError::InvalidContract)?
        .into_bytes();
    if inputs.whir_epochs.len() != 2
        || inputs.whir_folds.len() != 2 * WHIR_FOLD_COUNT_PER_EPOCH
        || inputs.response_merkle_geometries.len() != inputs.response_component_roles.len()
        || inputs.response_merkle_geometries.len() != inputs.proof_wire_geometry.responses().len()
        || inputs.response_merkle_geometries.len() != inputs.verifier_moves.len()
    {
        return Err(CompactMaskingCoefficientMapError::InvalidContract);
    }

    let mut maps = Vec::new();
    let mut fold_map_ordinals = Vec::with_capacity(inputs.whir_folds.len());
    for fold in inputs.whir_folds {
        let private_coordinate_count = checked_product(&[
            fold.oracle_width,
            checked_add(fold.message_length, fold.hiding_randomness_length)?,
        ])?;
        maps.push(CompactCoefficientToViewMap {
            coordinate: CompactMaskingMapCoordinate {
                role: CompactMaskingViewRole::Source,
                epoch: fold.epoch,
                batch_ordinal: fold.batch_ordinal,
                coordinate: 0,
            },
            private_coordinate_count,
            view_coordinate_count: fold.oracle_width,
            projection: CompactCoefficientProjection::FoldedReedSolomonSource {
                lane_count: fold.oracle_width,
                message_length_per_lane: fold.message_length,
                randomness_length_per_lane: fold.hiding_randomness_length,
                domain_size: fold.block_length,
                maximum_query_count: fold.query_count,
            },
            surjectivity: CompactSurjectivityWitness::ReedSolomonRandomnessMinor {
                randomness_length: fold.hiding_randomness_length,
                maximum_query_count: fold.query_count,
            },
        });

        let fold_map_ordinal = maps.len();
        maps.push(CompactCoefficientToViewMap {
            coordinate: CompactMaskingMapCoordinate {
                role: CompactMaskingViewRole::Fold,
                epoch: fold.epoch,
                batch_ordinal: fold.batch_ordinal,
                coordinate: 0,
            },
            private_coordinate_count,
            view_coordinate_count: checked_add(fold.message_length, fold.hiding_randomness_length)?,
            projection: CompactCoefficientProjection::LimbFold {
                input_limb_count: fold.oracle_width,
                output_message_length: fold.message_length,
                output_randomness_length: fold.hiding_randomness_length,
            },
            surjectivity: CompactSurjectivityWitness::MultilinearEqualityPartitionOfUnity {
                limb_count: fold.oracle_width,
            },
        });
        fold_map_ordinals.push(fold_map_ordinal);
    }

    let mut carried_map_ordinals_by_epoch = vec![Vec::new(); inputs.whir_epochs.len()];
    for (epoch_index, epoch) in inputs.whir_epochs.iter().enumerate() {
        for (group_index, group) in epoch
            .external_mask_groups
            .iter()
            .chain(&epoch.internal_mask_groups)
            .enumerate()
        {
            let map_ordinal = maps.len();
            maps.push(carried_mask_map(epoch.epoch, group_index, *group)?);
            carried_map_ordinals_by_epoch[epoch_index].push(map_ordinal);
        }
    }

    for (epoch_index, epoch) in inputs.whir_epochs.iter().enumerate() {
        let final_source_index =
            epoch_index * WHIR_FOLD_COUNT_PER_EPOCH + (WHIR_FOLD_COUNT_PER_EPOCH - 1);
        let fold_map_ordinal = fold_map_ordinals[final_source_index];
        let (source_message_coordinate_count, source_randomness_coordinate_count) =
            match maps[fold_map_ordinal].projection {
                CompactCoefficientProjection::LimbFold {
                    output_message_length,
                    output_randomness_length,
                    ..
                } => (output_message_length, output_randomness_length),
                _ => return Err(CompactMaskingCoefficientMapError::InvalidProjection),
            };
        let source_coordinate_count = checked_add(
            source_message_coordinate_count,
            source_randomness_coordinate_count,
        )?;
        let hidden_source_private_coordinate_count = source_coordinate_count;
        let source_mirror_map_ordinal = maps.len();
        maps.push(CompactCoefficientToViewMap {
            coordinate: CompactMaskingMapCoordinate {
                role: CompactMaskingViewRole::Mirror,
                epoch: epoch.epoch,
                batch_ordinal: u8::try_from(WHIR_FOLD_COUNT_PER_EPOCH - 1)
                    .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
                coordinate: 0,
            },
            private_coordinate_count: checked_add(
                hidden_source_private_coordinate_count,
                source_coordinate_count,
            )?,
            view_coordinate_count: source_coordinate_count,
            projection: CompactCoefficientProjection::AffineMirror {
                carried_map_ordinal: fold_map_ordinal,
                hidden_private_coordinate_count: hidden_source_private_coordinate_count,
                coordinate_count: source_coordinate_count,
            },
            surjectivity: CompactSurjectivityWitness::FreshCoordinateIdentity {
                coordinate_count: source_coordinate_count,
            },
        });
        let first_mask_mirror_map_ordinal = maps.len();
        for (group_index, &carried_map_ordinal) in carried_map_ordinals_by_epoch[epoch_index]
            .iter()
            .enumerate()
        {
            let coordinate_count = maps[carried_map_ordinal].private_coordinate_count;
            maps.push(CompactCoefficientToViewMap {
                coordinate: CompactMaskingMapCoordinate {
                    role: CompactMaskingViewRole::Mirror,
                    epoch: epoch.epoch,
                    batch_ordinal: u8::try_from(group_index)
                        .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
                    coordinate: 1,
                },
                private_coordinate_count: checked_product(&[2, coordinate_count])?,
                view_coordinate_count: coordinate_count,
                projection: CompactCoefficientProjection::AffineMirror {
                    carried_map_ordinal,
                    hidden_private_coordinate_count: coordinate_count,
                    coordinate_count,
                },
                surjectivity: CompactSurjectivityWitness::FreshCoordinateIdentity {
                    coordinate_count,
                },
            });
        }
        let mut claim_dependencies = vec![CompactBaseCaseClaimDependency {
            mirror_map_ordinal: source_mirror_map_ordinal,
            lane_count: 1,
            message_length_per_lane: source_message_coordinate_count,
            randomness_length_per_lane: source_randomness_coordinate_count,
        }];
        for (group_index, group) in epoch
            .external_mask_groups
            .iter()
            .chain(&epoch.internal_mask_groups)
            .enumerate()
        {
            claim_dependencies.push(CompactBaseCaseClaimDependency {
                mirror_map_ordinal: first_mask_mirror_map_ordinal
                    .checked_add(group_index)
                    .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
                lane_count: group.width,
                message_length_per_lane: group.message_length,
                randomness_length_per_lane: group.randomness_length,
            });
        }
        let base_claim_private_coordinate_count =
            claim_dependencies
                .iter()
                .try_fold(0_u64, |count, dependency| {
                    checked_product(&[dependency.lane_count, dependency.message_length_per_lane])
                        .and_then(|dependency_count| checked_add(count, dependency_count))
                })?;
        maps.push(CompactCoefficientToViewMap {
            coordinate: CompactMaskingMapCoordinate {
                role: CompactMaskingViewRole::Terminal,
                epoch: epoch.epoch,
                batch_ordinal: 0,
                coordinate: 0,
            },
            private_coordinate_count: base_claim_private_coordinate_count,
            view_coordinate_count: 1,
            projection: CompactCoefficientProjection::WhirBaseCaseClaim {
                dependencies: claim_dependencies.clone(),
            },
            surjectivity: CompactSurjectivityWitness::InheritedFreshCoordinateCovector {
                dependency_count: u64::try_from(claim_dependencies.len())
                    .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
            },
        });
    }

    for (epoch_index, epoch) in inputs.whir_epochs.iter().enumerate() {
        for group in epoch
            .internal_mask_groups
            .iter()
            .filter(|group| group.role_tag == 5)
        {
            let fold_index =
                epoch_index * WHIR_FOLD_COUNT_PER_EPOCH + usize::from(group.coordinate);
            let fold_map_ordinal = *fold_map_ordinals
                .get(fold_index)
                .ok_or(CompactMaskingCoefficientMapError::InvalidContract)?;
            let (source_message_length, source_randomness_length) =
                match maps[fold_map_ordinal].projection {
                    CompactCoefficientProjection::LimbFold {
                        output_message_length,
                        output_randomness_length,
                        ..
                    } => (output_message_length, output_randomness_length),
                    _ => return Err(CompactMaskingCoefficientMapError::InvalidProjection),
                };
            if group.width != 1 || group.message_length != source_randomness_length {
                return Err(CompactMaskingCoefficientMapError::InvalidContract);
            }
            maps.push(CompactCoefficientToViewMap {
                coordinate: CompactMaskingMapCoordinate {
                    role: CompactMaskingViewRole::CodeSwitch,
                    epoch: epoch.epoch,
                    batch_ordinal: group.coordinate,
                    coordinate: 0,
                },
                private_coordinate_count: checked_add(
                    source_message_length,
                    source_randomness_length,
                )?,
                view_coordinate_count: group.message_length,
                projection: CompactCoefficientProjection::FoldedRandomnessSuffix {
                    fold_map_ordinal,
                    first_coordinate: source_message_length,
                    coordinate_count: group.message_length,
                },
                surjectivity: CompactSurjectivityWitness::InheritedCheckedMap {
                    map_ordinal: fold_map_ordinal,
                },
            });
        }
    }

    for epoch in inputs.whir_epochs {
        for group in epoch
            .internal_mask_groups
            .iter()
            .filter(|group| group.role_tag == 4)
        {
            if group.message_length != WHIR_SUMCHECK_MASK_MESSAGE_LENGTH
                || group.width != u64::from(epoch.folding_schedule[usize::from(group.coordinate)])
            {
                return Err(CompactMaskingCoefficientMapError::InvalidContract);
            }
            maps.push(CompactCoefficientToViewMap {
                coordinate: CompactMaskingMapCoordinate {
                    role: CompactMaskingViewRole::Sumcheck,
                    epoch: epoch.epoch,
                    batch_ordinal: group.coordinate,
                    coordinate: 0,
                },
                private_coordinate_count: checked_product(&[group.width, group.message_length])?,
                view_coordinate_count: whir_sumcheck_view_count(group.width, group.message_length)?,
                projection: CompactCoefficientProjection::WhirSumcheckTranscript {
                    round_count: group.width,
                    mask_message_length: group.message_length,
                },
                surjectivity: CompactSurjectivityWitness::WhirSumcheckConstantMinor {
                    round_count: group.width,
                },
            });
        }
    }

    let cfw_geometry = inputs.cfw_configuration.geometry();
    let cfw_round_count = u64::try_from(cfw_geometry.sumcheck_round_count())
        .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
    maps.push(CompactCoefficientToViewMap {
        coordinate: CompactMaskingMapCoordinate {
            role: CompactMaskingViewRole::Sumcheck,
            epoch: 0,
            batch_ordinal: 0,
            coordinate: 1,
        },
        private_coordinate_count: checked_product(&[
            cfw_round_count,
            u64::try_from(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        ])?,
        view_coordinate_count: cfw_outer_view_count(cfw_round_count)?,
        projection: CompactCoefficientProjection::CfwOuterTranscript {
            round_count: cfw_round_count,
        },
        surjectivity: CompactSurjectivityWitness::CfwOuterFullColumnRank {
            round_count: cfw_round_count,
        },
    });

    let cross_epoch = inputs.cfw_configuration.cross_epoch();
    maps.push(CompactCoefficientToViewMap {
        coordinate: CompactMaskingMapCoordinate {
            role: CompactMaskingViewRole::Quotient,
            epoch: 0,
            batch_ordinal: 0,
            coordinate: 0,
        },
        private_coordinate_count: cross_epoch.main_message_element_count,
        view_coordinate_count: cross_epoch.copied_element_count,
        projection: CompactCoefficientProjection::QuotientPrefix {
            copied_element_count: cross_epoch.copied_element_count,
            pre_challenge_element_count: cross_epoch.pre_challenge_message_element_count,
            main_element_count: cross_epoch.main_message_element_count,
        },
        surjectivity: CompactSurjectivityWitness::CoordinateIdentity,
    });
    maps.push(CompactCoefficientToViewMap {
        coordinate: CompactMaskingMapCoordinate {
            role: CompactMaskingViewRole::ExplicitPoint,
            epoch: 0,
            batch_ordinal: 0,
            coordinate: 0,
        },
        private_coordinate_count: cross_epoch
            .copied_element_count
            .checked_add(2)
            .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        view_coordinate_count: inputs
            .cfw_configuration
            .cross_epoch_disclosed_scalar_count(),
        projection: CompactCoefficientProjection::CrossEpochExplicitPoint {
            copied_element_count: cross_epoch.copied_element_count,
            point_coordinate_count: cross_epoch.point_coordinate_count,
        },
        surjectivity: CompactSurjectivityWitness::CrossEpochTwoMaskCorrection,
    });
    maps.push(CompactCoefficientToViewMap {
        coordinate: CompactMaskingMapCoordinate {
            role: CompactMaskingViewRole::Terminal,
            epoch: 0,
            batch_ordinal: 0,
            coordinate: 1,
        },
        private_coordinate_count: checked_product(&[
            cfw_round_count,
            u64::try_from(COMPACT_CFW_MATRIX_COUNT)
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
            2,
        ])?,
        view_coordinate_count: u64::try_from(COMPACT_CFW_MATRIX_COUNT)
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        projection: CompactCoefficientProjection::CfwInnerTerminal {
            round_count: cfw_round_count,
            matrix_count: u64::try_from(COMPACT_CFW_MATRIX_COUNT)
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        },
        surjectivity: CompactSurjectivityWitness::CfwTerminalDisjointRolePivots {
            matrix_count: u64::try_from(COMPACT_CFW_MATRIX_COUNT)
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        },
    });

    let mut response_component_embeddings = Vec::new();
    let mut construction_commitment_embeddings = Vec::new();
    let mut preceding_commitment_count = 0_u32;
    for ((((geometry, component_roles), wire), verifier_move), response_index) in inputs
        .response_merkle_geometries
        .iter()
        .zip(inputs.response_component_roles)
        .zip(inputs.proof_wire_geometry.responses())
        .zip(inputs.verifier_moves)
        .zip(0_usize..)
    {
        if usize::try_from(geometry.response_ordinal()).ok() != Some(response_index)
            || geometry.response_ordinal() != wire.ordinal()
            || geometry.components().len() != component_roles.len()
            || usize::try_from(verifier_move.ordinal).ok() != Some(response_index)
        {
            return Err(CompactMaskingCoefficientMapError::InvalidContract);
        }
        let newly_embedded_commitment_count = verifier_move
            .preceding_commitment_count
            .checked_sub(preceding_commitment_count)
            .ok_or(CompactMaskingCoefficientMapError::InvalidContract)?;
        let first_new_commitment_ordinal = u32::try_from(construction_commitment_embeddings.len())
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
        for (component_index, (component, component_role)) in geometry
            .components()
            .iter()
            .zip(component_roles)
            .enumerate()
        {
            if !is_construction_commitment_component(component_role.role_tag) {
                continue;
            }
            let semantic_role = response_component_source_role(component_role.role_tag)?
                .ok_or(CompactMaskingCoefficientMapError::InvalidContract)?;
            if component_role.role_tag == 5 {
                let CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                    first_logical_verifier_move_ordinal,
                    first_distinct_query_group_ordinal,
                    second_logical_verifier_move_ordinal,
                    second_distinct_query_group_ordinal,
                } = component.query_selection()
                else {
                    return Err(CompactMaskingCoefficientMapError::InvalidContract);
                };
                append_commitment_embedding(
                    &mut construction_commitment_embeddings,
                    geometry.response_ordinal(),
                    component_index,
                    semantic_role,
                    *component_role,
                    CompactConstructionCommitmentOwnership::OwnedByPreChallengeEpochReusedByMainEpoch,
                    CompactCommitmentQuerySource::SharedCrossEpochUnion {
                        owned_pre_challenge: CompactCommitmentQueryCoordinate {
                            logical_verifier_move_ordinal:
                                first_logical_verifier_move_ordinal,
                            distinct_query_group_ordinal:
                                first_distinct_query_group_ordinal,
                        },
                        reused_main: CompactCommitmentQueryCoordinate {
                            logical_verifier_move_ordinal:
                                second_logical_verifier_move_ordinal,
                            distinct_query_group_ordinal:
                                second_distinct_query_group_ordinal,
                        },
                    },
                )?;
            } else {
                append_commitment_embedding(
                    &mut construction_commitment_embeddings,
                    geometry.response_ordinal(),
                    component_index,
                    semantic_role,
                    *component_role,
                    CompactConstructionCommitmentOwnership::OwnedByEpoch {
                        epoch: construction_commitment_owner_epoch(*component_role)?,
                    },
                    CompactCommitmentQuerySource::Component,
                )?;
            }
        }
        let actual_new_commitment_count = u32::try_from(construction_commitment_embeddings.len())
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?
            .checked_sub(first_new_commitment_ordinal)
            .ok_or(CompactMaskingCoefficientMapError::InvalidContract)?;
        if actual_new_commitment_count != newly_embedded_commitment_count {
            return Err(CompactMaskingCoefficientMapError::InvalidContract);
        }
        preceding_commitment_count = verifier_move.preceding_commitment_count;
        append_response_component_embeddings(
            &mut response_component_embeddings,
            geometry,
            component_roles,
        )?;
    }
    if preceding_commitment_count != 45 || construction_commitment_embeddings.len() != 45 {
        return Err(CompactMaskingCoefficientMapError::InvalidContract);
    }

    let certificate = CompactMaskingCoefficientMapCertificate {
        contract_source_hash,
        maps,
        response_component_embeddings,
        construction_commitment_embeddings,
    };
    certificate.check()?;
    Ok(certificate)
}

fn carried_mask_map(
    epoch: u8,
    group_index: usize,
    group: CompactWhirMaskGroupContract,
) -> Result<CompactCoefficientToViewMap, CompactMaskingCoefficientMapError> {
    let private_coordinate_count = checked_product(&[
        group.width,
        checked_add(group.message_length, group.randomness_length)?,
    ])?;
    Ok(CompactCoefficientToViewMap {
        coordinate: CompactMaskingMapCoordinate {
            role: CompactMaskingViewRole::CarriedMask,
            epoch,
            batch_ordinal: u8::try_from(group_index)
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
            coordinate: u32::from(group.role_tag),
        },
        private_coordinate_count,
        view_coordinate_count: group.width,
        projection: CompactCoefficientProjection::CarriedMaskReedSolomon {
            lane_count: group.width,
            message_length_per_lane: group.message_length,
            randomness_length_per_lane: group.randomness_length,
            domain_size: group.domain_size,
            maximum_query_count: group.randomness_length,
            contract_role_tag: group.role_tag,
        },
        surjectivity: CompactSurjectivityWitness::ReedSolomonRandomnessMinor {
            randomness_length: group.randomness_length,
            maximum_query_count: group.randomness_length,
        },
    })
}

fn append_response_component_embeddings(
    embeddings: &mut Vec<CompactResponseComponentEmbedding>,
    geometry: &CompactResponseMerkleGeometry,
    component_roles: &[CompactResponseComponentRoleContract],
) -> Result<(), CompactMaskingCoefficientMapError> {
    for (component_index, (component, contract_role)) in geometry
        .components()
        .iter()
        .zip(component_roles)
        .enumerate()
    {
        embeddings.push(CompactResponseComponentEmbedding {
            outer_response_ordinal: geometry.response_ordinal(),
            component_ordinal: u32::try_from(component_index)
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
            semantic_role: response_component_source_role(contract_role.role_tag)?,
            component_role: *contract_role,
            first_leaf_ordinal: component.first_leaf_ordinal(),
            leaf_count: component.leaf_count(),
            minimum_queried_leaf_count: component.minimum_queried_leaf_count(),
            maximum_queried_leaf_count: component.maximum_queried_leaf_count(),
            query_selection: component.query_selection(),
            value_kind: component.value_kind(),
            field_element_count_per_leaf: component.field_element_count_per_leaf(),
        });
    }
    Ok(())
}

pub(super) fn response_component_source_role(
    contract_role_tag: u8,
) -> Result<Option<CompactMaskingViewRole>, CompactMaskingCoefficientMapError> {
    let role = match contract_role_tag {
        1 | 3 => Some(CompactMaskingViewRole::Source),
        2 | 4 | 5 | 11 => Some(CompactMaskingViewRole::CarriedMask),
        6 => Some(CompactMaskingViewRole::ExplicitPoint),
        7 | 8 | 9 | 12 | 13 => Some(CompactMaskingViewRole::Sumcheck),
        10 | 18 | 19 => Some(CompactMaskingViewRole::Terminal),
        14 => Some(CompactMaskingViewRole::Fold),
        15 => Some(CompactMaskingViewRole::CodeSwitch),
        16 | 17 | 20 | 21 => Some(CompactMaskingViewRole::Mirror),
        22 => None,
        _ => return Err(CompactMaskingCoefficientMapError::InvalidContract),
    };
    Ok(role)
}

fn is_construction_commitment_component(component_role_tag: u8) -> bool {
    matches!(component_role_tag, 1..=5 | 11 | 14..=17)
}

fn construction_commitment_owner_epoch(
    role: CompactResponseComponentRoleContract,
) -> Result<u8, CompactMaskingCoefficientMapError> {
    match role.role_tag {
        1 => Ok(1),
        2..=4 => Ok(2),
        11 | 14..=17 if (1..=2).contains(&role.epoch) => Ok(role.epoch),
        _ => Err(CompactMaskingCoefficientMapError::InvalidContract),
    }
}

fn commitment_ownership_matches_component(
    ownership: CompactConstructionCommitmentOwnership,
    role: CompactResponseComponentRoleContract,
) -> bool {
    match ownership {
        CompactConstructionCommitmentOwnership::OwnedByEpoch { epoch } => {
            role.role_tag != 5 && construction_commitment_owner_epoch(role) == Ok(epoch)
        }
        CompactConstructionCommitmentOwnership::OwnedByPreChallengeEpochReusedByMainEpoch => {
            role.role_tag == 5
        }
    }
}

fn commitment_query_source_matches_component(
    source: CompactCommitmentQuerySource,
    selection: CompactResponseQuerySelection,
) -> bool {
    match (source, selection) {
        (
            CompactCommitmentQuerySource::Component,
            CompactResponseQuerySelection::Unqueried
            | CompactResponseQuerySelection::EveryLeaf
            | CompactResponseQuerySelection::VerifierMessageDistinctGroup { .. },
        ) => true,
        (
            CompactCommitmentQuerySource::SharedCrossEpochUnion {
                owned_pre_challenge,
                reused_main,
            },
            CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                first_logical_verifier_move_ordinal,
                first_distinct_query_group_ordinal,
                second_logical_verifier_move_ordinal,
                second_distinct_query_group_ordinal,
            },
        ) => {
            owned_pre_challenge.logical_verifier_move_ordinal == first_logical_verifier_move_ordinal
                && owned_pre_challenge.distinct_query_group_ordinal
                    == first_distinct_query_group_ordinal
                && reused_main.logical_verifier_move_ordinal == second_logical_verifier_move_ordinal
                && reused_main.distinct_query_group_ordinal == second_distinct_query_group_ordinal
        }
        _ => false,
    }
}

fn append_commitment_embedding(
    embeddings: &mut Vec<CompactConstructionCommitmentEmbedding>,
    outer_response_ordinal: u32,
    component_index: usize,
    semantic_role: CompactMaskingViewRole,
    component_role: CompactResponseComponentRoleContract,
    ownership: CompactConstructionCommitmentOwnership,
    query_source: CompactCommitmentQuerySource,
) -> Result<(), CompactMaskingCoefficientMapError> {
    embeddings.push(CompactConstructionCommitmentEmbedding {
        commitment_ordinal: u32::try_from(embeddings.len())
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        outer_response_ordinal,
        component_ordinal: u32::try_from(component_index)
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        semantic_role,
        component_role,
        ownership,
        query_source,
    });
    Ok(())
}

fn check_projection(
    map: &CompactCoefficientToViewMap,
    maps: &[CompactCoefficientToViewMap],
) -> Result<(), CompactMaskingCoefficientMapError> {
    match &map.projection {
        CompactCoefficientProjection::FoldedReedSolomonSource {
            lane_count,
            message_length_per_lane,
            randomness_length_per_lane,
            domain_size,
            maximum_query_count,
        }
        | CompactCoefficientProjection::CarriedMaskReedSolomon {
            lane_count,
            message_length_per_lane,
            randomness_length_per_lane,
            domain_size,
            maximum_query_count,
            ..
        } => {
            let dimension = checked_add(*message_length_per_lane, *randomness_length_per_lane)?;
            if !domain_size.is_power_of_two()
                || dimension > *domain_size
                || *maximum_query_count == 0
                || *maximum_query_count > *randomness_length_per_lane
                || map.private_coordinate_count != checked_product(&[*lane_count, dimension])?
                || map.view_coordinate_count != *lane_count
            {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
        }
        CompactCoefficientProjection::AffineMirror {
            carried_map_ordinal,
            hidden_private_coordinate_count,
            coordinate_count,
        } => {
            let carried = maps
                .get(*carried_map_ordinal)
                .ok_or(CompactMaskingCoefficientMapError::InvalidProjection)?;
            let expected_hidden_coordinate_count = match carried.projection {
                CompactCoefficientProjection::LimbFold { .. } => carried.view_coordinate_count,
                CompactCoefficientProjection::CarriedMaskReedSolomon { .. } => {
                    carried.private_coordinate_count
                }
                _ => return Err(CompactMaskingCoefficientMapError::InvalidProjection),
            };
            if *hidden_private_coordinate_count != expected_hidden_coordinate_count
                || map.private_coordinate_count
                    != checked_add(*hidden_private_coordinate_count, *coordinate_count)?
                || map.view_coordinate_count != *coordinate_count
            {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
        }
        CompactCoefficientProjection::FoldedRandomnessSuffix {
            fold_map_ordinal,
            first_coordinate,
            coordinate_count,
        } => {
            let fold = maps
                .get(*fold_map_ordinal)
                .ok_or(CompactMaskingCoefficientMapError::InvalidProjection)?;
            if !matches!(
                fold.projection,
                CompactCoefficientProjection::LimbFold { .. }
            ) || map.private_coordinate_count != fold.view_coordinate_count
                || first_coordinate.checked_add(*coordinate_count)
                    != Some(fold.view_coordinate_count)
                || map.view_coordinate_count != *coordinate_count
            {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
        }
        CompactCoefficientProjection::LimbFold {
            input_limb_count,
            output_message_length,
            output_randomness_length,
        } => {
            let output_count = checked_add(*output_message_length, *output_randomness_length)?;
            if *input_limb_count == 0
                || map.private_coordinate_count
                    != checked_product(&[*input_limb_count, output_count])?
                || map.view_coordinate_count != output_count
            {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
        }
        CompactCoefficientProjection::QuotientPrefix {
            copied_element_count,
            pre_challenge_element_count,
            main_element_count,
        } => {
            if *copied_element_count == 0
                || *copied_element_count > *pre_challenge_element_count
                || pre_challenge_element_count.checked_mul(2) != Some(*main_element_count)
                || map.private_coordinate_count != *main_element_count
                || map.view_coordinate_count != *copied_element_count
            {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
        }
        CompactCoefficientProjection::WhirSumcheckTranscript {
            round_count,
            mask_message_length,
        } => {
            if *round_count == 0
                || *mask_message_length < 3
                || map.private_coordinate_count
                    != checked_product(&[*round_count, *mask_message_length])?
                || map.view_coordinate_count
                    != whir_sumcheck_view_count(*round_count, *mask_message_length)?
            {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
        }
        CompactCoefficientProjection::CfwOuterTranscript { round_count } => {
            if *round_count == 0
                || map.private_coordinate_count
                    != checked_product(&[
                        *round_count,
                        u64::try_from(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
                            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
                    ])?
                || map.view_coordinate_count != cfw_outer_view_count(*round_count)?
            {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
        }
        CompactCoefficientProjection::CrossEpochExplicitPoint {
            copied_element_count,
            point_coordinate_count,
        } => {
            if *copied_element_count == 0
                || *point_coordinate_count == 0
                || map.private_coordinate_count != copied_element_count + 2
                || map.view_coordinate_count != 3
            {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
        }
        CompactCoefficientProjection::CfwInnerTerminal {
            round_count,
            matrix_count,
        } => {
            if *round_count == 0
                || *matrix_count
                    != u64::try_from(COMPACT_CFW_MATRIX_COUNT)
                        .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?
                || map.private_coordinate_count
                    != checked_product(&[*round_count, *matrix_count, 2])?
                || map.view_coordinate_count != *matrix_count
            {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
        }
        CompactCoefficientProjection::WhirBaseCaseClaim { dependencies } => {
            let mut expected_private_coordinate_count = 0_u64;
            if dependencies.is_empty() || map.view_coordinate_count != 1 {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
            for dependency in dependencies {
                let mirror = maps
                    .get(dependency.mirror_map_ordinal)
                    .ok_or(CompactMaskingCoefficientMapError::InvalidProjection)?;
                let full_coordinate_count = checked_product(&[
                    dependency.lane_count,
                    checked_add(
                        dependency.message_length_per_lane,
                        dependency.randomness_length_per_lane,
                    )?,
                ])?;
                if dependency.lane_count == 0
                    || dependency.message_length_per_lane == 0
                    || dependency.randomness_length_per_lane == 0
                    || mirror.view_coordinate_count != full_coordinate_count
                    || !matches!(
                        mirror.projection,
                        CompactCoefficientProjection::AffineMirror { .. }
                    )
                    || !matches!(
                        mirror.surjectivity,
                        CompactSurjectivityWitness::FreshCoordinateIdentity { .. }
                    )
                {
                    return Err(CompactMaskingCoefficientMapError::InvalidProjection);
                }
                expected_private_coordinate_count = checked_add(
                    expected_private_coordinate_count,
                    checked_product(&[dependency.lane_count, dependency.message_length_per_lane])?,
                )?;
            }
            if map.private_coordinate_count != expected_private_coordinate_count {
                return Err(CompactMaskingCoefficientMapError::InvalidProjection);
            }
        }
    }
    Ok(())
}

fn check_surjectivity_witness(
    map: &CompactCoefficientToViewMap,
) -> Result<(), CompactMaskingCoefficientMapError> {
    let matches_projection = match (map.surjectivity, &map.projection) {
        (
            CompactSurjectivityWitness::ReedSolomonRandomnessMinor {
                randomness_length,
                maximum_query_count,
            },
            CompactCoefficientProjection::FoldedReedSolomonSource {
                randomness_length_per_lane,
                maximum_query_count: projection_query_count,
                ..
            }
            | CompactCoefficientProjection::CarriedMaskReedSolomon {
                randomness_length_per_lane,
                maximum_query_count: projection_query_count,
                ..
            },
        ) => {
            randomness_length == *randomness_length_per_lane
                && maximum_query_count == *projection_query_count
        }
        (
            CompactSurjectivityWitness::MultilinearEqualityPartitionOfUnity { limb_count },
            CompactCoefficientProjection::LimbFold {
                input_limb_count, ..
            },
        ) => limb_count == *input_limb_count,
        (
            CompactSurjectivityWitness::FreshCoordinateIdentity { coordinate_count },
            CompactCoefficientProjection::AffineMirror {
                coordinate_count: projection_count,
                ..
            },
        ) => coordinate_count == *projection_count,
        (
            CompactSurjectivityWitness::CfwOuterFullColumnRank { round_count },
            CompactCoefficientProjection::CfwOuterTranscript {
                round_count: projection_count,
            },
        ) => round_count == *projection_count,
        (
            CompactSurjectivityWitness::WhirSumcheckConstantMinor { round_count },
            CompactCoefficientProjection::WhirSumcheckTranscript {
                round_count: projection_count,
                mask_message_length,
            },
        ) => round_count == *projection_count && *mask_message_length == 3,
        (
            CompactSurjectivityWitness::CfwTerminalDisjointRolePivots { matrix_count },
            CompactCoefficientProjection::CfwInnerTerminal {
                matrix_count: projection_count,
                ..
            },
        ) => matrix_count == *projection_count,
        (
            CompactSurjectivityWitness::CrossEpochTwoMaskCorrection,
            CompactCoefficientProjection::CrossEpochExplicitPoint { .. },
        ) => true,
        (CompactSurjectivityWitness::CoordinateIdentity, projection) => matches!(
            projection,
            CompactCoefficientProjection::QuotientPrefix { .. }
        ),
        (CompactSurjectivityWitness::InheritedCheckedMap { .. }, projection) => matches!(
            projection,
            CompactCoefficientProjection::FoldedRandomnessSuffix { .. }
        ),
        (
            CompactSurjectivityWitness::InheritedFreshCoordinateCovector { dependency_count },
            CompactCoefficientProjection::WhirBaseCaseClaim { dependencies },
        ) => usize::try_from(dependency_count).ok() == Some(dependencies.len()),
        _ => false,
    };
    if !matches_projection {
        return Err(CompactMaskingCoefficientMapError::InvalidProjection);
    }
    Ok(())
}

fn checked_add(left: u64, right: u64) -> Result<u64, CompactMaskingCoefficientMapError> {
    left.checked_add(right)
        .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)
}

fn checked_product(values: &[u64]) -> Result<u64, CompactMaskingCoefficientMapError> {
    values.iter().try_fold(1_u64, |product, value| {
        product
            .checked_mul(*value)
            .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)
    })
}

fn whir_sumcheck_view_count(
    round_count: u64,
    mask_message_length: u64,
) -> Result<u64, CompactMaskingCoefficientMapError> {
    checked_product(&[
        round_count,
        mask_message_length
            .checked_sub(1)
            .ok_or(CompactMaskingCoefficientMapError::InvalidProjection)?,
    ])?
    .checked_add(1)
    .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)
}

fn cfw_outer_view_count(round_count: u64) -> Result<u64, CompactMaskingCoefficientMapError> {
    checked_product(&[
        round_count,
        u64::try_from(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH + 1)
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
    ])?
    .checked_add(1)
    .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)
}

struct ProjectionConditionalImageInput<'a> {
    maps: &'a [CompactCoefficientToViewMap],
    map_ordinal: usize,
    map: &'a CompactCoefficientToViewMap,
    first_output_coordinate: u64,
    output_coordinate_count: u64,
    independent_coordinate_count: u64,
    preceding_output_values: &'a [CompactChallengeField],
    runtime: CompactConditionalImageRuntime<'a>,
}

fn prepare_projection_conditional_image(
    input: ProjectionConditionalImageInput<'_>,
) -> Result<CompactConditionalImageExpansion, CompactMaskingCoefficientMapError> {
    let ProjectionConditionalImageInput {
        maps,
        map_ordinal,
        map,
        first_output_coordinate,
        output_coordinate_count,
        independent_coordinate_count,
        preceding_output_values,
        runtime,
    } = input;
    let end = first_output_coordinate
        .checked_add(output_coordinate_count)
        .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
    if output_coordinate_count == 0
        || (!matches!(
            map.projection,
            CompactCoefficientProjection::FoldedReedSolomonSource { .. }
                | CompactCoefficientProjection::CarriedMaskReedSolomon { .. }
        ) && end > map.view_coordinate_count)
        || usize::try_from(first_output_coordinate).ok() != Some(preceding_output_values.len())
    {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }

    match (&map.projection, runtime) {
        (
            CompactCoefficientProjection::FoldedReedSolomonSource { .. }
            | CompactCoefficientProjection::CarriedMaskReedSolomon { .. },
            CompactConditionalImageRuntime::ReedSolomonQueries {
                preceding_query_positions,
                query_positions,
            },
        ) => prepare_reed_solomon_conditional_image(
            map,
            preceding_query_positions,
            query_positions,
            first_output_coordinate,
            output_coordinate_count,
            independent_coordinate_count,
            preceding_output_values,
        ),
        (
            CompactCoefficientProjection::AffineMirror { .. },
            CompactConditionalImageRuntime::AffineMirrorQueries {
                query_positions,
                retained_mirror_coefficients,
            },
        ) => prepare_affine_mirror_query_image(
            maps,
            map_ordinal,
            map,
            query_positions,
            retained_mirror_coefficients,
            first_output_coordinate,
            output_coordinate_count,
            independent_coordinate_count,
            preceding_output_values,
        ),
        (
            CompactCoefficientProjection::WhirSumcheckTranscript { .. },
            CompactConditionalImageRuntime::WhirSumcheck { round_challenges },
        ) => prepare_dense_conditional_image(
            map,
            first_output_coordinate,
            output_coordinate_count,
            independent_coordinate_count,
            preceding_output_values,
            |private| {
                let masks = private
                    .chunks_exact(WHIR_SUMCHECK_MASK_MESSAGE_LENGTH as usize)
                    .map(<[_]>::to_vec)
                    .collect::<Vec<_>>();
                apply_whir_sumcheck_mask_prefix(
                    &masks,
                    round_challenges,
                    usize::try_from(
                        first_output_coordinate
                            .checked_add(output_coordinate_count)
                            .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
                    )
                    .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
                )
            },
        ),
        (
            CompactCoefficientProjection::CfwOuterTranscript { .. },
            CompactConditionalImageRuntime::CfwOuter { round_challenges },
        ) => prepare_dense_conditional_image(
            map,
            first_output_coordinate,
            output_coordinate_count,
            independent_coordinate_count,
            preceding_output_values,
            |private| {
                let masks = private
                    .chunks_exact(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
                    .map(|mask| {
                        let mut values =
                            [CompactChallengeField::ZERO; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH];
                        values.copy_from_slice(mask);
                        values
                    })
                    .collect::<Vec<_>>();
                apply_cfw_outer_mask_prefix(
                    &masks,
                    round_challenges,
                    usize::try_from(
                        first_output_coordinate
                            .checked_add(output_coordinate_count)
                            .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
                    )
                    .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
                )
            },
        ),
        (
            CompactCoefficientProjection::CrossEpochExplicitPoint {
                copied_element_count,
                point_coordinate_count,
            },
            CompactConditionalImageRuntime::CrossEpochExplicitPoint,
        ) => {
            if *copied_element_count == 0
                || *point_coordinate_count == 0
                || map.private_coordinate_count
                    != copied_element_count
                        .checked_add(2)
                        .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?
                || map.view_coordinate_count != 3
                || first_output_coordinate != 0
                || output_coordinate_count != 3
                || independent_coordinate_count != 2
                || !preceding_output_values.is_empty()
            {
                return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
            }
            Ok(CompactConditionalImageExpansion::Dense {
                offset: vec![CompactChallengeField::ZERO; 3],
                basis: vec![
                    vec![
                        CompactChallengeField::ONE,
                        CompactChallengeField::ZERO,
                        CompactChallengeField::ONE,
                    ],
                    vec![
                        CompactChallengeField::ZERO,
                        CompactChallengeField::ONE,
                        -CompactChallengeField::ONE,
                    ],
                ],
                pivot_output_coordinates: vec![0, 1],
            })
        }
        (
            CompactCoefficientProjection::CfwInnerTerminal { .. },
            CompactConditionalImageRuntime::CfwInnerTerminal { round_challenges },
        ) => prepare_dense_conditional_image(
            map,
            first_output_coordinate,
            output_coordinate_count,
            independent_coordinate_count,
            preceding_output_values,
            |private| {
                let coefficients = private
                    .chunks_exact(2)
                    .map(|pair| [pair[0], pair[1]])
                    .collect::<Vec<_>>();
                Ok(apply_cfw_inner_terminal_view(&coefficients, round_challenges)?.to_vec())
            },
        ),
        _ => Err(CompactMaskingCoefficientMapError::InvalidConditionalImage),
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_affine_mirror_query_image(
    maps: &[CompactCoefficientToViewMap],
    map_ordinal: usize,
    map: &CompactCoefficientToViewMap,
    query_positions: &[u64],
    retained_mirror_coefficients: &[CompactChallengeField],
    first_output_coordinate: u64,
    output_coordinate_count: u64,
    independent_coordinate_count: u64,
    preceding_output_values: &[CompactChallengeField],
) -> Result<CompactConditionalImageExpansion, CompactMaskingCoefficientMapError> {
    let CompactCoefficientProjection::AffineMirror {
        carried_map_ordinal,
        ..
    } = map.projection
    else {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    };
    let carried = maps
        .get(carried_map_ordinal)
        .ok_or(CompactMaskingCoefficientMapError::InvalidConditionalImage)?;
    let (lane_count, message_length, randomness_length, domain_size, maximum_query_count) =
        match carried.projection {
            CompactCoefficientProjection::CarriedMaskReedSolomon {
                lane_count,
                message_length_per_lane,
                randomness_length_per_lane,
                domain_size,
                maximum_query_count,
                ..
            } => (
                lane_count,
                message_length_per_lane,
                randomness_length_per_lane,
                domain_size,
                maximum_query_count,
            ),
            CompactCoefficientProjection::LimbFold {
                input_limb_count,
                output_message_length,
                output_randomness_length,
            } => {
                let source = maps[..map_ordinal]
                    .iter()
                    .find(|candidate| {
                        candidate.coordinate.role == CompactMaskingViewRole::Source
                            && candidate.coordinate.epoch == map.coordinate.epoch
                            && candidate.coordinate.batch_ordinal == map.coordinate.batch_ordinal
                    })
                    .ok_or(CompactMaskingCoefficientMapError::InvalidConditionalImage)?;
                let CompactCoefficientProjection::FoldedReedSolomonSource {
                    lane_count: source_lane_count,
                    message_length_per_lane,
                    randomness_length_per_lane,
                    domain_size,
                    maximum_query_count,
                    ..
                } = source.projection
                else {
                    return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
                };
                if source_lane_count != input_limb_count
                    || message_length_per_lane != output_message_length
                    || randomness_length_per_lane != output_randomness_length
                {
                    return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
                }
                (
                    1,
                    message_length_per_lane,
                    randomness_length_per_lane,
                    domain_size,
                    maximum_query_count,
                )
            }
            _ => return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage),
        };
    let query_count = u64::try_from(query_positions.len())
        .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
    let expected_output_count = lane_count
        .checked_mul(query_count)
        .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
    if query_positions.is_empty()
        || query_count > maximum_query_count
        || query_positions
            .iter()
            .any(|position| *position >= domain_size)
        || query_positions
            .windows(2)
            .any(|window| window[0] >= window[1])
        || first_output_coordinate != 0
        || output_coordinate_count != expected_output_count
        || independent_coordinate_count != 0
        || !preceding_output_values.is_empty()
        || u64::try_from(retained_mirror_coefficients.len()).ok() != Some(map.view_coordinate_count)
    {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let lane_dimension = usize::try_from(
        message_length
            .checked_add(randomness_length)
            .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
    )
    .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
    let generator = CompactChallengeField::two_adic_generator(
        usize::try_from(domain_size.ilog2())
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
    );
    let mut offset = Vec::with_capacity(
        usize::try_from(expected_output_count)
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
    );
    // Canonical response transport is query-major: each queried Merkle leaf
    // contains every lane value before the next queried leaf begins.
    for position in query_positions {
        for lane in retained_mirror_coefficients.chunks_exact(lane_dimension) {
            offset.push(apply_reed_solomon_query(generator, *position, lane));
        }
    }
    Ok(CompactConditionalImageExpansion::Dense {
        offset,
        basis: Vec::new(),
        pivot_output_coordinates: Vec::new(),
    })
}

fn prepare_reed_solomon_conditional_image(
    map: &CompactCoefficientToViewMap,
    preceding_query_positions: &[u64],
    query_positions: &[u64],
    first_output_coordinate: u64,
    output_coordinate_count: u64,
    independent_coordinate_count: u64,
    preceding_output_values: &[CompactChallengeField],
) -> Result<CompactConditionalImageExpansion, CompactMaskingCoefficientMapError> {
    let (lane_count, message_length, randomness_length, domain_size, maximum_query_count) =
        match map.projection {
            CompactCoefficientProjection::FoldedReedSolomonSource {
                lane_count,
                message_length_per_lane,
                randomness_length_per_lane,
                domain_size,
                maximum_query_count,
            }
            | CompactCoefficientProjection::CarriedMaskReedSolomon {
                lane_count,
                message_length_per_lane,
                randomness_length_per_lane,
                domain_size,
                maximum_query_count,
                ..
            } => (
                lane_count,
                message_length_per_lane,
                randomness_length_per_lane,
                domain_size,
                maximum_query_count,
            ),
            _ => return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage),
        };
    let mut distinct_query_positions = preceding_query_positions
        .iter()
        .chain(query_positions)
        .copied()
        .collect::<Vec<_>>();
    distinct_query_positions.sort_unstable();
    distinct_query_positions.dedup();
    let distinct_query_count = distinct_query_positions.len();
    if query_positions.is_empty()
        || u64::try_from(distinct_query_count)
            .ok()
            .is_none_or(|count| count > maximum_query_count || count > randomness_length)
        || preceding_query_positions
            .iter()
            .chain(query_positions)
            .any(|position| *position >= domain_size)
        || preceding_query_positions
            .windows(2)
            .any(|window| window[0] >= window[1])
        || query_positions
            .windows(2)
            .any(|window| window[0] >= window[1])
    {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let preceding_output_count = lane_count
        .checked_mul(
            u64::try_from(preceding_query_positions.len())
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        )
        .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
    let output_count = lane_count
        .checked_mul(
            u64::try_from(query_positions.len())
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        )
        .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
    let lane_dimension = message_length
        .checked_add(randomness_length)
        .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
    if lane_count == 0
        || message_length == 0
        || randomness_length == 0
        || !domain_size.is_power_of_two()
        || lane_dimension > domain_size
        || maximum_query_count == 0
        || maximum_query_count > randomness_length
        || map.private_coordinate_count
            != lane_count
                .checked_mul(lane_dimension)
                .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?
        || map.view_coordinate_count != lane_count
        || map.surjectivity
            != (CompactSurjectivityWitness::ReedSolomonRandomnessMinor {
                randomness_length,
                maximum_query_count,
            })
        || first_output_coordinate != preceding_output_count
        || usize::try_from(preceding_output_count).ok() != Some(preceding_output_values.len())
        || output_coordinate_count != output_count
    {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }

    // The certified randomness minor makes the evaluation map onto every
    // distinct query coordinate surjective up to `maximum_query_count`.
    // Conditioned outputs therefore need only copy overlaps from the retained
    // prefix and inject one fresh ideal coordinate for every novel query/lane.
    // Output coordinates are query-major because one Merkle leaf carries all
    // lane values for a query position.
    let new_query_count = query_positions
        .iter()
        .filter(|position| preceding_query_positions.binary_search(position).is_err())
        .count();
    let expected_independent_coordinate_count = lane_count
        .checked_mul(
            u64::try_from(new_query_count)
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        )
        .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
    if independent_coordinate_count != expected_independent_coordinate_count {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }

    let output_count = usize::try_from(output_count)
        .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
    let lane_count = usize::try_from(lane_count)
        .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
    let mut offset = vec![CompactChallengeField::ZERO; output_count];
    let mut independent_output_coordinates = Vec::with_capacity(
        usize::try_from(expected_independent_coordinate_count)
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
    );
    for (current_query_ordinal, position) in query_positions.iter().enumerate() {
        for lane_ordinal in 0..lane_count {
            let output_coordinate = current_query_ordinal
                .checked_mul(lane_count)
                .and_then(|first| first.checked_add(lane_ordinal))
                .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
            match preceding_query_positions.binary_search(position) {
                Ok(preceding_query_ordinal) => {
                    let preceding_output_coordinate = preceding_query_ordinal
                        .checked_mul(lane_count)
                        .and_then(|first| first.checked_add(lane_ordinal))
                        .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
                    offset[output_coordinate] =
                        preceding_output_values[preceding_output_coordinate];
                }
                Err(_) => independent_output_coordinates.push(
                    u64::try_from(output_coordinate)
                        .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
                ),
            }
        }
    }
    Ok(CompactConditionalImageExpansion::CoordinateInjection {
        offset,
        independent_output_coordinates,
    })
}

fn prepare_dense_conditional_image(
    map: &CompactCoefficientToViewMap,
    first_output_coordinate: u64,
    output_coordinate_count: u64,
    independent_coordinate_count: u64,
    preceding_output_values: &[CompactChallengeField],
    apply: impl Fn(
        &[CompactChallengeField],
    ) -> Result<Vec<CompactChallengeField>, CompactMaskingCoefficientMapError>,
) -> Result<CompactConditionalImageExpansion, CompactMaskingCoefficientMapError> {
    prepare_dense_conditional_image_with_dimensions(
        usize::try_from(map.private_coordinate_count)
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        usize::try_from(
            first_output_coordinate
                .checked_add(output_coordinate_count)
                .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        )
        .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        usize::try_from(first_output_coordinate)
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        usize::try_from(output_coordinate_count)
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        usize::try_from(independent_coordinate_count)
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        preceding_output_values,
        apply,
    )
    .and_then(|expansion| {
        let expected = usize::try_from(output_coordinate_count)
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
        match &expansion {
            CompactConditionalImageExpansion::Dense { offset, .. } if offset.len() == expected => {
                Ok(expansion)
            }
            _ => Err(CompactMaskingCoefficientMapError::InvalidConditionalImage),
        }
    })
}

fn prepare_dense_conditional_image_with_dimensions(
    private_coordinate_count: usize,
    view_coordinate_count: usize,
    first_output_coordinate: usize,
    output_coordinate_count: usize,
    independent_coordinate_count: usize,
    preceding_output_values: &[CompactChallengeField],
    apply: impl Fn(
        &[CompactChallengeField],
    ) -> Result<Vec<CompactChallengeField>, CompactMaskingCoefficientMapError>,
) -> Result<CompactConditionalImageExpansion, CompactMaskingCoefficientMapError> {
    if private_coordinate_count == 0
        || first_output_coordinate != preceding_output_values.len()
        || first_output_coordinate
            .checked_add(output_coordinate_count)
            .is_none_or(|end| end > view_coordinate_count)
    {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let zero = vec![CompactChallengeField::ZERO; private_coordinate_count];
    let affine_origin = apply(&zero)?;
    if affine_origin.len() != view_coordinate_count {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let mut matrix =
        vec![vec![CompactChallengeField::ZERO; private_coordinate_count]; view_coordinate_count];
    for private_coordinate in 0..private_coordinate_count {
        let mut basis_input = zero.clone();
        basis_input[private_coordinate] = CompactChallengeField::ONE;
        let output = apply(&basis_input)?;
        if output.len() != view_coordinate_count {
            return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
        }
        for (output_coordinate, value) in output.into_iter().enumerate() {
            matrix[output_coordinate][private_coordinate] =
                value - affine_origin[output_coordinate];
        }
    }

    let prefix_rows = &matrix[..first_output_coordinate];
    let prefix_target = preceding_output_values
        .iter()
        .zip(&affine_origin[..first_output_coordinate])
        .map(|(value, origin)| *value - *origin)
        .collect::<Vec<_>>();
    let particular = solve_linear_system(prefix_rows, &prefix_target, private_coordinate_count)?;
    let prefix_kernel = nullspace_basis(prefix_rows, private_coordinate_count)?;
    let current_end = first_output_coordinate + output_coordinate_count;
    let current_rows = &matrix[first_output_coordinate..current_end];
    let current_offset = current_rows
        .iter()
        .zip(&affine_origin[first_output_coordinate..current_end])
        .map(|(row, origin)| *origin + dot(row, &particular))
        .collect::<Vec<_>>();
    let image_generators = prefix_kernel
        .iter()
        .map(|kernel_vector| {
            current_rows
                .iter()
                .map(|row| dot(row, kernel_vector))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let (basis, pivot_output_coordinates) = canonical_image_basis(image_generators)?;
    if basis.len() != independent_coordinate_count {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let normalized_offset =
        normalize_affine_offset(current_offset, &basis, &pivot_output_coordinates)?;
    Ok(CompactConditionalImageExpansion::Dense {
        offset: normalized_offset,
        basis,
        pivot_output_coordinates,
    })
}

fn validate_conditional_expansion(
    output_coordinate_count: u64,
    independent_coordinate_count: u64,
    expansion: &CompactConditionalImageExpansion,
) -> Result<(), CompactMaskingCoefficientMapError> {
    let output_count = usize::try_from(output_coordinate_count)
        .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
    match expansion {
        CompactConditionalImageExpansion::Dense {
            offset,
            basis,
            pivot_output_coordinates,
        } => {
            if offset.len() != output_count
                || u64::try_from(basis.len()).ok() != Some(independent_coordinate_count)
                || basis.iter().any(|vector| vector.len() != output_count)
                || pivot_output_coordinates.len() != basis.len()
            {
                return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
            }
            for (basis_ordinal, pivot) in pivot_output_coordinates.iter().copied().enumerate() {
                let pivot = usize::try_from(pivot)
                    .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
                if pivot >= output_count
                    || offset[pivot] != CompactChallengeField::ZERO
                    || basis.iter().enumerate().any(|(other, vector)| {
                        vector[pivot]
                            != if other == basis_ordinal {
                                CompactChallengeField::ONE
                            } else {
                                CompactChallengeField::ZERO
                            }
                    })
                {
                    return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
                }
            }
        }
        CompactConditionalImageExpansion::CoordinateInjection {
            offset,
            independent_output_coordinates,
        } => {
            if offset.len() != output_count
                || u64::try_from(independent_output_coordinates.len()).ok()
                    != Some(independent_coordinate_count)
                || independent_output_coordinates
                    .windows(2)
                    .any(|coordinates| coordinates[0] >= coordinates[1])
                || independent_output_coordinates.iter().any(|coordinate| {
                    usize::try_from(*coordinate).ok().is_none_or(|coordinate| {
                        coordinate >= output_count
                            || offset[coordinate] != CompactChallengeField::ZERO
                    })
                })
            {
                return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
            }
        }
    }
    Ok(())
}

fn solve_linear_system(
    rows: &[Vec<CompactChallengeField>],
    target: &[CompactChallengeField],
    column_count: usize,
) -> Result<Vec<CompactChallengeField>, CompactMaskingCoefficientMapError> {
    if rows.len() != target.len() || rows.iter().any(|row| row.len() != column_count) {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let mut augmented = rows
        .iter()
        .zip(target)
        .map(|(row, value)| {
            let mut augmented_row = row.clone();
            augmented_row.push(*value);
            augmented_row
        })
        .collect::<Vec<_>>();
    let pivots = row_reduce(&mut augmented, column_count)?;
    if augmented.iter().any(|row| {
        row[..column_count]
            .iter()
            .all(|value| *value == CompactChallengeField::ZERO)
            && row[column_count] != CompactChallengeField::ZERO
    }) {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let mut solution = vec![CompactChallengeField::ZERO; column_count];
    for (row_ordinal, pivot_column) in pivots {
        solution[pivot_column] = augmented[row_ordinal][column_count];
    }
    Ok(solution)
}

fn nullspace_basis(
    rows: &[Vec<CompactChallengeField>],
    column_count: usize,
) -> Result<Vec<Vec<CompactChallengeField>>, CompactMaskingCoefficientMapError> {
    if rows.iter().any(|row| row.len() != column_count) {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let mut reduced = rows.to_vec();
    let pivots = row_reduce(&mut reduced, column_count)?;
    let mut pivot_rows = vec![None; column_count];
    for (row_ordinal, pivot_column) in pivots {
        pivot_rows[pivot_column] = Some(row_ordinal);
    }
    let mut basis = Vec::with_capacity(column_count);
    for free_column in 0..column_count {
        if pivot_rows[free_column].is_some() {
            continue;
        }
        let mut vector = vec![CompactChallengeField::ZERO; column_count];
        vector[free_column] = CompactChallengeField::ONE;
        for (pivot_column, row_ordinal) in pivot_rows.iter().copied().enumerate() {
            if let Some(row_ordinal) = row_ordinal {
                vector[pivot_column] = -reduced[row_ordinal][free_column];
            }
        }
        basis.push(vector);
    }
    Ok(basis)
}

fn row_reduce(
    rows: &mut [Vec<CompactChallengeField>],
    coefficient_column_count: usize,
) -> Result<Vec<(usize, usize)>, CompactMaskingCoefficientMapError> {
    if rows.iter().any(|row| row.len() < coefficient_column_count) {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let mut pivot_row = 0_usize;
    let mut pivots = Vec::new();
    for pivot_column in 0..coefficient_column_count {
        let Some(selected_row) = (pivot_row..rows.len())
            .find(|row| rows[*row][pivot_column] != CompactChallengeField::ZERO)
        else {
            continue;
        };
        rows.swap(pivot_row, selected_row);
        let inverse = rows[pivot_row][pivot_column].inverse();
        for value in &mut rows[pivot_row] {
            *value *= inverse;
        }
        let normalized_pivot = rows[pivot_row].clone();
        for (row_ordinal, row) in rows.iter_mut().enumerate() {
            if row_ordinal == pivot_row || row[pivot_column] == CompactChallengeField::ZERO {
                continue;
            }
            let scale = row[pivot_column];
            for (value, pivot_value) in row.iter_mut().zip(&normalized_pivot) {
                *value -= scale * *pivot_value;
            }
        }
        pivots.push((pivot_row, pivot_column));
        pivot_row += 1;
        if pivot_row == rows.len() {
            break;
        }
    }
    Ok(pivots)
}

fn canonical_image_basis(
    generators: Vec<Vec<CompactChallengeField>>,
) -> Result<(Vec<Vec<CompactChallengeField>>, Vec<u64>), CompactMaskingCoefficientMapError> {
    let output_coordinate_count = generators.first().map_or(0, Vec::len);
    if generators
        .iter()
        .any(|generator| generator.len() != output_coordinate_count)
    {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let mut basis: Vec<Vec<CompactChallengeField>> = Vec::new();
    let mut pivots = Vec::new();
    for mut generator in generators {
        for (basis_vector, pivot) in basis.iter().zip(&pivots) {
            let scale = generator[*pivot];
            for (value, basis_value) in generator.iter_mut().zip(basis_vector) {
                *value -= scale * *basis_value;
            }
        }
        let Some(pivot) = generator
            .iter()
            .position(|value| *value != CompactChallengeField::ZERO)
        else {
            continue;
        };
        let inverse = generator[pivot].inverse();
        for value in &mut generator {
            *value *= inverse;
        }
        for basis_vector in &mut basis {
            let scale = basis_vector[pivot];
            for (value, new_basis_value) in basis_vector.iter_mut().zip(&generator) {
                *value -= scale * *new_basis_value;
            }
        }
        basis.push(generator);
        pivots.push(pivot);
    }
    let pivots = pivots
        .into_iter()
        .map(|pivot| {
            u64::try_from(pivot).map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((basis, pivots))
}

fn normalize_affine_offset(
    mut offset: Vec<CompactChallengeField>,
    basis: &[Vec<CompactChallengeField>],
    pivots: &[u64],
) -> Result<Vec<CompactChallengeField>, CompactMaskingCoefficientMapError> {
    for (basis_vector, pivot) in basis.iter().zip(pivots) {
        let pivot = usize::try_from(*pivot)
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?;
        let scale = *offset
            .get(pivot)
            .ok_or(CompactMaskingCoefficientMapError::InvalidConditionalImage)?;
        for (value, basis_value) in offset.iter_mut().zip(basis_vector) {
            *value -= scale * *basis_value;
        }
    }
    Ok(offset)
}

fn dot(left: &[CompactChallengeField], right: &[CompactChallengeField]) -> CompactChallengeField {
    left.iter()
        .zip(right)
        .map(|(left, right)| *left * *right)
        .sum()
}

/// Coefficient of one private lane coordinate in one Reed-Solomon query.
pub(crate) fn reed_solomon_query_coefficient(
    domain_generator: CompactChallengeField,
    position: u64,
    coefficient_ordinal: u64,
) -> CompactChallengeField {
    domain_generator
        .exp_u64(position)
        .exp_u64(coefficient_ordinal)
}

pub(crate) fn apply_reed_solomon_query(
    domain_generator: CompactChallengeField,
    position: u64,
    coefficients: &[CompactChallengeField],
) -> CompactChallengeField {
    let point = domain_generator.exp_u64(position);
    coefficients
        .iter()
        .rev()
        .fold(CompactChallengeField::ZERO, |value, coefficient| {
            value * point + *coefficient
        })
}

/// Applies the complete limb-major fold projection.
#[cfg(test)]
pub(crate) fn apply_limb_fold(
    limb_major_values: &[CompactChallengeField],
    output_coordinate_count: usize,
    equality_weights: &[CompactChallengeField],
) -> Result<Vec<CompactChallengeField>, CompactMaskingCoefficientMapError> {
    if output_coordinate_count == 0
        || equality_weights.is_empty()
        || limb_major_values.len()
            != output_coordinate_count
                .checked_mul(equality_weights.len())
                .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?
    {
        return Err(CompactMaskingCoefficientMapError::InvalidProjection);
    }
    let mut folded = vec![CompactChallengeField::ZERO; output_coordinate_count];
    for (limb_ordinal, weight) in equality_weights.iter().copied().enumerate() {
        let first = limb_ordinal * output_coordinate_count;
        for (destination, source) in folded
            .iter_mut()
            .zip(&limb_major_values[first..first + output_coordinate_count])
        {
            *destination += weight * *source;
        }
    }
    Ok(folded)
}

#[cfg(test)]
pub(crate) fn apply_affine_mirror(
    carried: &[CompactChallengeField],
    fresh: &[CompactChallengeField],
    challenge: CompactChallengeField,
) -> Result<Vec<CompactChallengeField>, CompactMaskingCoefficientMapError> {
    if carried.len() != fresh.len() || carried.is_empty() {
        return Err(CompactMaskingCoefficientMapError::InvalidProjection);
    }
    Ok(carried
        .iter()
        .zip(fresh)
        .map(|(carried, fresh)| *fresh + challenge * *carried)
        .collect())
}

/// Returns the authenticated main-source prefix copied into the earlier
/// quotient source. The remaining earlier-source coordinates are fixed zero
/// padding and therefore expose no private coordinate through this map.
#[cfg(test)]
pub(crate) fn apply_quotient_prefix_view(
    main_source: &[CompactChallengeField],
    copied_element_count: usize,
    pre_challenge_element_count: usize,
) -> Result<&[CompactChallengeField], CompactMaskingCoefficientMapError> {
    if copied_element_count == 0
        || copied_element_count > pre_challenge_element_count
        || pre_challenge_element_count.checked_mul(2) != Some(main_source.len())
    {
        return Err(CompactMaskingCoefficientMapError::InvalidProjection);
    }
    Ok(&main_source[..copied_element_count])
}

/// Applies the fresh-message covector used by the real WHIR base-case
/// producer before its affine blinding challenge is sampled.
#[cfg(test)]
pub(crate) fn apply_whir_base_case_claim_view(
    fresh_message_coordinates: &[CompactChallengeField],
    fresh_claim_covector: &[CompactChallengeField],
) -> Result<CompactChallengeField, CompactMaskingCoefficientMapError> {
    if fresh_message_coordinates.is_empty()
        || fresh_message_coordinates.len() != fresh_claim_covector.len()
        || fresh_claim_covector
            .iter()
            .all(|coefficient| *coefficient == CompactChallengeField::ZERO)
    {
        return Err(CompactMaskingCoefficientMapError::InvalidProjection);
    }
    Ok(fresh_message_coordinates
        .iter()
        .zip(fresh_claim_covector)
        .map(|(value, coefficient)| *value * *coefficient)
        .sum())
}

/// Applies the exact mask-only portion of a WHIR sumcheck transcript.
/// Output is `mu_tilde`, then `[c0,c2,...]` for every round.
#[cfg(test)]
pub(crate) fn apply_whir_sumcheck_mask_view(
    masks: &[Vec<CompactChallengeField>],
    round_challenges: &[CompactChallengeField],
) -> Result<Vec<CompactChallengeField>, CompactMaskingCoefficientMapError> {
    if masks.is_empty()
        || masks.len() != round_challenges.len()
        || masks[0].len() < 3
        || masks.iter().any(|mask| mask.len() != masks[0].len())
    {
        return Err(CompactMaskingCoefficientMapError::InvalidProjection);
    }
    let round_count = masks.len();
    let endpoint_sum = |mask: &[CompactChallengeField]| {
        mask[0] * CompactChallengeField::TWO
            + mask[1..].iter().copied().sum::<CompactChallengeField>()
    };
    let mut view = Vec::with_capacity(1 + round_count * (masks[0].len() - 1));
    let hypercube_multiplicity = CompactChallengeField::TWO.exp_u64(
        u64::try_from(round_count - 1)
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
    );
    view.push(
        hypercube_multiplicity
            * masks
                .iter()
                .map(|mask| endpoint_sum(mask))
                .sum::<CompactChallengeField>(),
    );
    for round_ordinal in 0..round_count {
        let suffix_scale = CompactChallengeField::TWO.exp_u64(
            u64::try_from(round_count - round_ordinal - 1)
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        );
        let past = masks[..round_ordinal]
            .iter()
            .zip(&round_challenges[..round_ordinal])
            .map(|(mask, challenge)| evaluate_polynomial(mask, *challenge))
            .sum::<CompactChallengeField>();
        let future = masks[round_ordinal + 1..]
            .iter()
            .map(|mask| endpoint_sum(mask))
            .sum::<CompactChallengeField>();
        let mut constant = suffix_scale * (past + masks[round_ordinal][0]);
        if round_ordinal + 1 < round_count {
            constant += suffix_scale * CompactChallengeField::TWO.inverse() * future;
        }
        view.push(constant);
        view.extend(
            masks[round_ordinal][2..]
                .iter()
                .map(|coefficient| suffix_scale * *coefficient),
        );
    }
    Ok(view)
}

fn apply_whir_sumcheck_mask_prefix(
    masks: &[Vec<CompactChallengeField>],
    preceding_round_challenges: &[CompactChallengeField],
    output_end: usize,
) -> Result<Vec<CompactChallengeField>, CompactMaskingCoefficientMapError> {
    if masks.is_empty()
        || masks[0].len() != WHIR_SUMCHECK_MASK_MESSAGE_LENGTH as usize
        || masks.iter().any(|mask| mask.len() != masks[0].len())
        || output_end == 0
    {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let transmitted_round_width = masks[0].len() - 1;
    let round_output_count = output_end - 1;
    if !round_output_count.is_multiple_of(transmitted_round_width) {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let disclosed_round_count = round_output_count / transmitted_round_width;
    if disclosed_round_count > masks.len()
        || disclosed_round_count.saturating_sub(1) > preceding_round_challenges.len()
        || preceding_round_challenges.len() > masks.len()
    {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let endpoint_sum = |mask: &[CompactChallengeField]| {
        mask[0] * CompactChallengeField::TWO
            + mask[1..].iter().copied().sum::<CompactChallengeField>()
    };
    let mut view = Vec::with_capacity(output_end);
    view.push(
        CompactChallengeField::TWO.exp_u64(
            u64::try_from(masks.len() - 1)
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        ) * masks
            .iter()
            .map(|mask| endpoint_sum(mask))
            .sum::<CompactChallengeField>(),
    );
    for round_ordinal in 0..disclosed_round_count {
        let suffix_scale = CompactChallengeField::TWO.exp_u64(
            u64::try_from(masks.len() - round_ordinal - 1)
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        );
        let past = masks[..round_ordinal]
            .iter()
            .zip(&preceding_round_challenges[..round_ordinal])
            .map(|(mask, challenge)| evaluate_polynomial(mask, *challenge))
            .sum::<CompactChallengeField>();
        let future = masks[round_ordinal + 1..]
            .iter()
            .map(|mask| endpoint_sum(mask))
            .sum::<CompactChallengeField>();
        let mut constant = suffix_scale * (past + masks[round_ordinal][0]);
        if round_ordinal + 1 < masks.len() {
            constant += suffix_scale * CompactChallengeField::TWO.inverse() * future;
        }
        view.push(constant);
        view.extend(
            masks[round_ordinal][2..]
                .iter()
                .map(|coefficient| suffix_scale * *coefficient),
        );
    }
    Ok(view)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwOuterMaskView {
    pub(crate) auxiliary_target: CompactChallengeField,
    pub(crate) round_polynomials:
        Vec<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
    pub(crate) outer_evaluations: Vec<CompactChallengeField>,
}

/// Applies the independently derived complete compact-CFW outer-mask map.
pub(crate) fn apply_cfw_outer_mask_view(
    masks: &[[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]],
    round_challenges: &[CompactChallengeField],
) -> Result<CompactCfwOuterMaskView, CompactMaskingCoefficientMapError> {
    if masks.is_empty() || masks.len() != round_challenges.len() {
        return Err(CompactMaskingCoefficientMapError::InvalidProjection);
    }
    let round_count = masks.len();
    let endpoint_sum = |mask: &[CompactChallengeField]| {
        mask[0] * CompactChallengeField::TWO
            + mask[1..].iter().copied().sum::<CompactChallengeField>()
    };
    let auxiliary_target = CompactChallengeField::TWO.exp_u64(
        u64::try_from(round_count - 1)
            .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
    ) * masks
        .iter()
        .map(|mask| endpoint_sum(mask))
        .sum::<CompactChallengeField>();
    let mut round_polynomials = Vec::with_capacity(round_count);
    for round_ordinal in 0..round_count {
        let suffix_scale = CompactChallengeField::TWO.exp_u64(
            u64::try_from(round_count - round_ordinal - 1)
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        );
        let past = masks[..round_ordinal]
            .iter()
            .zip(&round_challenges[..round_ordinal])
            .map(|(mask, challenge)| evaluate_polynomial(mask, *challenge))
            .sum::<CompactChallengeField>();
        let future = masks[round_ordinal + 1..]
            .iter()
            .map(|mask| endpoint_sum(mask))
            .sum::<CompactChallengeField>();
        let mut polynomial = masks[round_ordinal].map(|coefficient| suffix_scale * coefficient);
        polynomial[0] += suffix_scale * past;
        if round_ordinal + 1 < round_count {
            polynomial[0] += suffix_scale * CompactChallengeField::TWO.inverse() * future;
        }
        round_polynomials.push(polynomial);
    }
    let outer_evaluations = masks
        .iter()
        .zip(round_challenges)
        .map(|(mask, challenge)| evaluate_polynomial(mask, *challenge))
        .collect();
    Ok(CompactCfwOuterMaskView {
        auxiliary_target,
        round_polynomials,
        outer_evaluations,
    })
}

fn apply_cfw_outer_mask_prefix(
    masks: &[[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]],
    preceding_round_challenges: &[CompactChallengeField],
    output_end: usize,
) -> Result<Vec<CompactChallengeField>, CompactMaskingCoefficientMapError> {
    if masks.is_empty() || output_end == 0 || preceding_round_challenges.len() > masks.len() {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let round_output_end = 1 + masks.len() * COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH;
    let disclosed_round_count = if output_end <= round_output_end {
        let round_output_count = output_end - 1;
        if !round_output_count.is_multiple_of(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH) {
            return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
        }
        round_output_count / COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH
    } else if output_end == round_output_end + masks.len()
        && preceding_round_challenges.len() == masks.len()
    {
        masks.len()
    } else {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    };
    if disclosed_round_count.saturating_sub(1) > preceding_round_challenges.len() {
        return Err(CompactMaskingCoefficientMapError::InvalidConditionalImage);
    }
    let endpoint_sum = |mask: &[CompactChallengeField]| {
        mask[0] * CompactChallengeField::TWO
            + mask[1..].iter().copied().sum::<CompactChallengeField>()
    };
    let mut view = Vec::with_capacity(output_end);
    view.push(
        CompactChallengeField::TWO.exp_u64(
            u64::try_from(masks.len() - 1)
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        ) * masks
            .iter()
            .map(|mask| endpoint_sum(mask))
            .sum::<CompactChallengeField>(),
    );
    for round_ordinal in 0..disclosed_round_count {
        let suffix_scale = CompactChallengeField::TWO.exp_u64(
            u64::try_from(masks.len() - round_ordinal - 1)
                .map_err(|_| CompactMaskingCoefficientMapError::ArithmeticOverflow)?,
        );
        let past = masks[..round_ordinal]
            .iter()
            .zip(&preceding_round_challenges[..round_ordinal])
            .map(|(mask, challenge)| evaluate_polynomial(mask, *challenge))
            .sum::<CompactChallengeField>();
        let future = masks[round_ordinal + 1..]
            .iter()
            .map(|mask| endpoint_sum(mask))
            .sum::<CompactChallengeField>();
        let mut polynomial = masks[round_ordinal].map(|coefficient| suffix_scale * coefficient);
        polynomial[0] += suffix_scale * past;
        if round_ordinal + 1 < masks.len() {
            polynomial[0] += suffix_scale * CompactChallengeField::TWO.inverse() * future;
        }
        view.extend(polynomial);
    }
    if output_end > round_output_end {
        view.extend(
            masks
                .iter()
                .zip(preceding_round_challenges)
                .map(|(mask, challenge)| evaluate_polynomial(mask, *challenge)),
        );
    }
    Ok(view)
}

/// Applies the complete compact-CFW inner-mask projection to the three
/// terminal values. Input order is round-major, then matrix-major, with the
/// two independent coefficients `(a,b)` of `[0,a,b,-a-b]`.
pub(crate) fn apply_cfw_inner_terminal_view(
    independent_coefficients: &[[CompactChallengeField; 2]],
    round_challenges: &[CompactChallengeField],
) -> Result<[CompactChallengeField; COMPACT_CFW_MATRIX_COUNT], CompactMaskingCoefficientMapError> {
    if round_challenges.is_empty()
        || independent_coefficients.len()
            != round_challenges
                .len()
                .checked_mul(COMPACT_CFW_MATRIX_COUNT)
                .ok_or(CompactMaskingCoefficientMapError::ArithmeticOverflow)?
    {
        return Err(CompactMaskingCoefficientMapError::InvalidProjection);
    }
    let multiplier = CompactChallengeField::from_u64(COMPACT_CFW_INNER_MASK_APPLICATION_MULTIPLIER);
    let mut terminal = [CompactChallengeField::ZERO; COMPACT_CFW_MATRIX_COUNT];
    for (round_ordinal, challenge) in round_challenges.iter().copied().enumerate() {
        let challenge_squared = challenge * challenge;
        let challenge_cubed = challenge_squared * challenge;
        let first_weight = multiplier * (challenge - challenge_cubed);
        let second_weight = multiplier * (challenge_squared - challenge_cubed);
        for (matrix_ordinal, destination) in terminal.iter_mut().enumerate() {
            let [first, second] =
                independent_coefficients[round_ordinal * COMPACT_CFW_MATRIX_COUNT + matrix_ordinal];
            *destination += first_weight * first + second_weight * second;
        }
    }
    Ok(terminal)
}

/// Applies the exact cross-epoch disclosure projection.
#[cfg(test)]
pub(crate) fn apply_cross_epoch_explicit_point_view(
    copied_source: &[CompactChallengeField],
    equality_covector_prefix: &[CompactChallengeField],
    pre_challenge_mask: CompactChallengeField,
    main_mask: CompactChallengeField,
) -> Result<[CompactChallengeField; 3], CompactMaskingCoefficientMapError> {
    if copied_source.is_empty() || copied_source.len() != equality_covector_prefix.len() {
        return Err(CompactMaskingCoefficientMapError::InvalidProjection);
    }
    let evaluation = copied_source
        .iter()
        .zip(equality_covector_prefix)
        .map(|(source, coefficient)| *source * *coefficient)
        .sum::<CompactChallengeField>();
    Ok([
        evaluation + pre_challenge_mask,
        evaluation + main_mask,
        pre_challenge_mask - main_mask,
    ])
}

fn evaluate_polynomial(
    coefficients: &[CompactChallengeField],
    point: CompactChallengeField,
) -> CompactChallengeField {
    coefficients
        .iter()
        .rev()
        .fold(CompactChallengeField::ZERO, |value, coefficient| {
            value * point + *coefficient
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_cfw::{
        CompactCfwMaskMaterial, CompactCfwScalarProverState,
    };
    use crate::bgv::proof_suite::compact_cfw_geometry::CompactCfwGeometry;
    use crate::bgv::proof_suite::compact_public_key_static_catalog::assert_selected_masking_producer_differentials;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::TwoAdicField;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::Matrix;
    use p3_multilinear_util::{point::Point, poly::Poly};
    use p3_whir::{FoldedRsCode, MaskCodeShape, switch_mask_covector};

    fn zero_inner_masks(geometry: CompactCfwGeometry) -> Vec<[CompactChallengeField; 4]> {
        vec![[CompactChallengeField::ZERO; 4]; geometry.inner_mask_count()]
    }

    fn zero_outer_masks(
        geometry: CompactCfwGeometry,
    ) -> Vec<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]> {
        vec![
            [CompactChallengeField::ZERO; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH];
            geometry.outer_mask_count()
        ]
    }

    fn production_cfw_outer_view(
        outer_masks: Vec<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
        round_challenges: &[CompactChallengeField],
    ) -> CompactCfwOuterMaskView {
        let witness_length = 1_usize << (round_challenges.len() - 1);
        let geometry = CompactCfwGeometry::derive(witness_length).expect("CFW test geometry");
        let material = CompactCfwMaskMaterial::from_canonical_messages(
            geometry,
            zero_inner_masks(geometry),
            outer_masks,
        )
        .expect("canonical outer masks");
        let mut state = CompactCfwScalarProverState::begin(
            geometry,
            material,
            CompactChallengeField::ZERO,
            (0..round_challenges.len())
                .map(|ordinal| CompactChallengeField::from_u64(101 + ordinal as u64))
                .collect(),
        )
        .expect("real scalar prover state");
        let auxiliary_target = state.auxiliary_target();
        let mut round_polynomials = Vec::with_capacity(round_challenges.len());
        for (round_ordinal, challenge) in round_challenges.iter().copied().enumerate() {
            let mut accumulator = state.round_accumulator().expect("real round accumulator");
            let suffix_count = 1_usize << (round_challenges.len() - round_ordinal - 1);
            for _ in 0..suffix_count {
                accumulator
                    .absorb_next_row_pair(
                        [CompactChallengeField::ZERO; COMPACT_CFW_MATRIX_COUNT],
                        [CompactChallengeField::ZERO; COMPACT_CFW_MATRIX_COUNT],
                    )
                    .expect("real zero matrix row pair");
            }
            let polynomial = accumulator.finish().expect("real round finish");
            state
                .accept_round_polynomial(polynomial)
                .expect("real round polynomial");
            state
                .bind_round_challenge(challenge)
                .expect("real round challenge");
            round_polynomials.push(polynomial);
        }
        let finish = state
            .finish([CompactChallengeField::ZERO; COMPACT_CFW_MATRIX_COUNT])
            .expect("real CFW finish");
        CompactCfwOuterMaskView {
            auxiliary_target,
            round_polynomials,
            outer_evaluations: finish.outer_evaluations().to_vec(),
        }
    }

    fn selected_fold_maps(
        certificate: &CompactMaskingCoefficientMapCertificate,
    ) -> impl Iterator<Item = &CompactCoefficientToViewMap> {
        certificate
            .maps()
            .iter()
            .filter(|map| map.coordinate.role == CompactMaskingViewRole::Fold)
    }

    #[test]
    fn selected_source_and_carried_rs_maps_match_production_encoders() {
        let certificate = derive_selected_compact_masking_coefficient_map_certificate()
            .expect("selected coefficient maps derive");
        let dft = Radix2DFTSmallBatch::<Goldilocks>::default();
        for map in certificate.maps().iter().filter(|map| {
            matches!(
                map.projection,
                CompactCoefficientProjection::FoldedReedSolomonSource { .. }
                    | CompactCoefficientProjection::CarriedMaskReedSolomon { .. }
            )
        }) {
            let (message_length, randomness_length, domain_size, source_code) = match map.projection
            {
                CompactCoefficientProjection::FoldedReedSolomonSource {
                    message_length_per_lane,
                    randomness_length_per_lane,
                    domain_size,
                    ..
                } => (
                    usize::try_from(message_length_per_lane).expect("message length fits"),
                    usize::try_from(randomness_length_per_lane).expect("randomness length fits"),
                    usize::try_from(domain_size).expect("domain size fits"),
                    true,
                ),
                CompactCoefficientProjection::CarriedMaskReedSolomon {
                    message_length_per_lane,
                    randomness_length_per_lane,
                    domain_size,
                    ..
                } => (
                    usize::try_from(message_length_per_lane).expect("message length fits"),
                    usize::try_from(randomness_length_per_lane).expect("randomness length fits"),
                    usize::try_from(domain_size).expect("domain size fits"),
                    false,
                ),
                _ => unreachable!("filtered projection"),
            };
            let message = (0..message_length)
                .map(|ordinal| CompactChallengeField::from_u64(17 + ordinal as u64))
                .collect::<Vec<_>>();
            let randomness = (0..randomness_length)
                .map(|ordinal| CompactChallengeField::from_u64(101 + ordinal as u64))
                .collect::<Vec<_>>();
            let mut coefficients = message.clone();
            coefficients.extend_from_slice(&randomness);
            let positions = [0, 1, 17, domain_size / 2 - 1, domain_size - 1];
            if source_code {
                let code =
                    FoldedRsCode::<Goldilocks>::new(message_length, randomness_length, domain_size);
                let encoded = code.encode_column(&dft, &message, &randomness);
                let generator = CompactChallengeField::from(code.domain_gen);
                for position in positions {
                    let expected =
                        apply_reed_solomon_query(generator, position as u64, &coefficients);
                    assert_eq!(
                        code.evaluate_at(position, &message, &randomness),
                        expected,
                        "source evaluate-at mismatch at {position}",
                    );
                    assert_eq!(
                        encoded.get(position, 0),
                        Some(expected),
                        "source encoded row mismatch at {position}",
                    );
                }
            } else {
                let log_inverse_rate = usize::try_from(domain_size.ilog2())
                    .expect("log domain fits")
                    - (message_length + randomness_length)
                        .next_power_of_two()
                        .ilog2() as usize;
                let shape = MaskCodeShape::new(message_length, randomness_length, log_inverse_rate);
                assert_eq!(shape.domain_size, domain_size);
                let encoded = shape.encode_with_randomness(&message, &randomness);
                let generator = CompactChallengeField::two_adic_generator(
                    usize::try_from(domain_size.ilog2()).expect("log domain fits"),
                );
                for position in positions {
                    assert_eq!(
                        encoded.get(position, 0),
                        Some(apply_reed_solomon_query(
                            generator,
                            position as u64,
                            &coefficients,
                        )),
                        "carried-mask encoded row mismatch at {position}",
                    );
                }
            }
        }
    }

    #[test]
    fn selected_sumcheck_and_base_case_maps_match_real_p3_producers() {
        assert_selected_masking_producer_differentials();
    }

    #[test]
    fn selected_limb_fold_maps_match_production_multilinear_evaluation() {
        let certificate = derive_selected_compact_masking_coefficient_map_certificate()
            .expect("selected coefficient maps derive");
        assert_eq!(selected_fold_maps(&certificate).count(), 8);
        for map in selected_fold_maps(&certificate) {
            let CompactCoefficientProjection::LimbFold {
                input_limb_count,
                output_message_length,
                output_randomness_length,
            } = map.projection
            else {
                unreachable!("filtered fold map")
            };
            let output_coordinate_count =
                usize::try_from(output_message_length + output_randomness_length)
                    .expect("fold output fits");
            let fold_variable_count =
                usize::try_from(input_limb_count.ilog2()).expect("fold variable count fits");
            let point = Point::new(
                (0..fold_variable_count)
                    .map(|ordinal| CompactChallengeField::from_u64(3 + ordinal as u64))
                    .collect(),
            );
            let equality_weights =
                Poly::new_from_point(point.as_slice(), CompactChallengeField::ONE);
            let selected_coordinates = [
                0,
                1.min(output_coordinate_count - 1),
                17.min(output_coordinate_count - 1),
                output_coordinate_count / 2,
                output_coordinate_count - 1,
            ];
            let mut limb_major_values = vec![
                CompactChallengeField::ZERO;
                output_coordinate_count * input_limb_count as usize
            ];
            for limb in 0..input_limb_count as usize {
                for &coordinate in &selected_coordinates {
                    limb_major_values[limb * output_coordinate_count + coordinate] =
                        CompactChallengeField::from_u64(23 + 7 * limb as u64 + coordinate as u64);
                }
            }
            let actual = apply_limb_fold(
                &limb_major_values,
                output_coordinate_count,
                equality_weights.as_slice(),
            )
            .expect("independent selected fold");
            for coordinate in selected_coordinates {
                let gathered = (0..input_limb_count as usize)
                    .map(|limb| limb_major_values[limb * output_coordinate_count + coordinate])
                    .collect::<Vec<_>>();
                assert_eq!(
                    actual[coordinate],
                    Poly::new(gathered).eval_ext::<Goldilocks>(&point),
                    "epoch {}, batch {}, coordinate {coordinate}",
                    map.coordinate.epoch,
                    map.coordinate.batch_ordinal,
                );
            }
        }
    }

    #[test]
    fn selected_code_switch_maps_are_exact_folded_randomness_suffixes() {
        let certificate = derive_selected_compact_masking_coefficient_map_certificate()
            .expect("selected coefficient maps derive");
        let code_switches = certificate
            .maps()
            .iter()
            .filter(|map| map.coordinate.role == CompactMaskingViewRole::CodeSwitch)
            .collect::<Vec<_>>();
        assert_eq!(code_switches.len(), 6);
        for map in code_switches {
            let CompactCoefficientProjection::FoldedRandomnessSuffix {
                fold_map_ordinal,
                first_coordinate,
                coordinate_count,
            } = map.projection
            else {
                unreachable!("filtered code switch")
            };
            let fold = &certificate.maps()[fold_map_ordinal];
            assert_eq!(
                first_coordinate + coordinate_count,
                fold.view_coordinate_count,
            );
            assert_eq!(map.private_coordinate_count, fold.view_coordinate_count);
            let query_points = [
                CompactChallengeField::from_u64(3),
                CompactChallengeField::from_u64(5),
            ];
            let query_coefficients = [
                CompactChallengeField::from_u64(7),
                CompactChallengeField::from_u64(11),
            ];
            let actual = switch_mask_covector(
                usize::try_from(first_coordinate).expect("message length fits"),
                usize::try_from(coordinate_count).expect("randomness length fits"),
                0,
                &[],
                &[],
                &query_points,
                &query_coefficients,
            );
            let expected = (0..coordinate_count)
                .map(|randomness_ordinal| {
                    query_points
                        .iter()
                        .zip(query_coefficients)
                        .map(|(point, coefficient)| {
                            coefficient * point.exp_u64(first_coordinate + randomness_ordinal)
                        })
                        .sum()
                })
                .collect::<Vec<_>>();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn selected_certificate_covers_every_affine_role_and_construction_commitment() {
        let certificate = derive_selected_compact_masking_coefficient_map_certificate()
            .expect("selected coefficient maps derive from contract bytes");
        assert_eq!(certificate.covered_roles(), [true; 9]);
        assert_eq!(
            certificate.response_component_embeddings().len(),
            selected_compact_public_key_proof_contract()
                .expect("selected contract")
                .verifier_inputs()
                .response_merkle_geometries
                .iter()
                .map(|geometry| geometry.components().len())
                .sum::<usize>()
        );
        assert_eq!(certificate.construction_commitment_embeddings().len(), 45);
        let external_mask_commitments = certificate
            .construction_commitment_embeddings()
            .iter()
            .filter(|embedding| matches!(embedding.component_role.role_tag, 2 | 4 | 5))
            .collect::<Vec<_>>();
        assert_eq!(external_mask_commitments.len(), 3);
        assert_eq!(
            certificate.construction_commitment_embeddings().len()
                - external_mask_commitments.len(),
            42,
        );
        let shared = certificate
            .construction_commitment_embeddings()
            .iter()
            .filter(|embedding| {
                matches!(
                    embedding.ownership,
                    CompactConstructionCommitmentOwnership::OwnedByPreChallengeEpochReusedByMainEpoch
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].component_role.role_tag, 5);
        assert!(matches!(
            shared[0].query_source,
            CompactCommitmentQuerySource::SharedCrossEpochUnion {
                owned_pre_challenge,
                reused_main,
            } if owned_pre_challenge != reused_main
        ));
        let contract = selected_compact_public_key_proof_contract().expect("selected contract");
        let inputs = contract.verifier_inputs();
        let mut preceding_commitment_count = 0_u32;
        for (response_ordinal, verifier_move) in inputs.verifier_moves.iter().enumerate() {
            let expected_delta =
                verifier_move.preceding_commitment_count - preceding_commitment_count;
            let actual_delta = certificate
                .construction_commitment_embeddings()
                .iter()
                .filter(|embedding| {
                    usize::try_from(embedding.outer_response_ordinal).ok() == Some(response_ordinal)
                })
                .count();
            assert_eq!(
                u32::try_from(actual_delta).expect("delta fits"),
                expected_delta
            );
            preceding_commitment_count = verifier_move.preceding_commitment_count;
        }
        assert_eq!(
            certificate
                .construction_commitment_embeddings()
                .iter()
                .filter(|embedding| embedding.outer_response_ordinal == 1)
                .count(),
            4,
        );
    }

    #[test]
    fn shared_cross_epoch_commitment_refuses_collapsed_or_swapped_query_unions() {
        let certificate = derive_selected_compact_masking_coefficient_map_certificate()
            .expect("selected coefficient maps derive");
        let shared = certificate
            .construction_commitment_embeddings()
            .iter()
            .find(|embedding| {
                matches!(
                    embedding.ownership,
                    CompactConstructionCommitmentOwnership::OwnedByPreChallengeEpochReusedByMainEpoch
                )
            })
            .expect("one shared cross-epoch commitment");
        let component = certificate
            .response_component_embeddings()
            .iter()
            .find(|component| {
                component.outer_response_ordinal == shared.outer_response_ordinal
                    && component.component_ordinal == shared.component_ordinal
            })
            .expect("shared component embedding");
        let CompactCommitmentQuerySource::SharedCrossEpochUnion {
            owned_pre_challenge,
            reused_main,
        } = shared.query_source
        else {
            panic!("shared commitment has a union query source")
        };
        assert!(commitment_query_source_matches_component(
            shared.query_source,
            component.query_selection,
        ));
        assert!(!commitment_query_source_matches_component(
            CompactCommitmentQuerySource::SharedCrossEpochUnion {
                owned_pre_challenge: reused_main,
                reused_main: owned_pre_challenge,
            },
            component.query_selection,
        ));
        assert!(!commitment_query_source_matches_component(
            CompactCommitmentQuerySource::SharedCrossEpochUnion {
                owned_pre_challenge,
                reused_main: owned_pre_challenge,
            },
            component.query_selection,
        ));
        assert!(!commitment_ownership_matches_component(
            CompactConstructionCommitmentOwnership::OwnedByEpoch { epoch: 1 },
            shared.component_role,
        ));
    }

    #[test]
    fn cfw_outer_map_matches_unmodified_real_accumulator() {
        for round_count in 2..=4 {
            let challenges = (0..round_count)
                .map(|ordinal| CompactChallengeField::from_u64(3 + 2 * ordinal as u64))
                .collect::<Vec<_>>();
            let column_count = round_count * COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH;
            for column_ordinal in 0..column_count {
                let mut masks = vec![
                    [CompactChallengeField::ZERO;
                        COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH];
                    round_count
                ];
                masks[column_ordinal / COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]
                    [column_ordinal % COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH] =
                    CompactChallengeField::ONE;
                assert_eq!(
                    apply_cfw_outer_mask_view(&masks, &challenges)
                        .expect("independent basis projection"),
                    production_cfw_outer_view(masks, &challenges),
                    "round count {round_count}, basis column {column_ordinal}",
                );
            }
            let dense = (0..round_count)
                .map(|round_ordinal| {
                    core::array::from_fn(|coefficient_ordinal| {
                        CompactChallengeField::from_u64(
                            31 + (round_ordinal * COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH
                                + coefficient_ordinal) as u64,
                        )
                    })
                })
                .collect::<Vec<_>>();
            assert_eq!(
                apply_cfw_outer_mask_view(&dense, &challenges)
                    .expect("independent dense projection"),
                production_cfw_outer_view(dense, &challenges),
            );
        }
    }

    #[test]
    fn selected_cfw_terminal_map_matches_real_prover_finish() {
        let geometry = CompactCfwGeometry::derive(4_194_304).expect("selected CFW geometry");
        assert_eq!(geometry.sumcheck_round_count(), 23);
        let challenges = (0..geometry.sumcheck_round_count())
            .map(|ordinal| CompactChallengeField::from_u64(2 + ordinal as u64))
            .collect::<Vec<_>>();
        let private_count = geometry.inner_mask_count() * 2;
        for selected_private_coordinates in
            [(0..private_count).map(Some).collect::<Vec<_>>(), vec![None]]
        {
            for selected_private_coordinate in selected_private_coordinates {
                let independent = (0..geometry.inner_mask_count())
                    .map(|mask_ordinal| {
                        if let Some(selected) = selected_private_coordinate {
                            [
                                if 2 * mask_ordinal == selected {
                                    CompactChallengeField::ONE
                                } else {
                                    CompactChallengeField::ZERO
                                },
                                if 2 * mask_ordinal + 1 == selected {
                                    CompactChallengeField::ONE
                                } else {
                                    CompactChallengeField::ZERO
                                },
                            ]
                        } else {
                            [
                                CompactChallengeField::from_u64(11 + 2 * mask_ordinal as u64),
                                CompactChallengeField::from_u64(12 + 2 * mask_ordinal as u64),
                            ]
                        }
                    })
                    .collect::<Vec<_>>();
                let inner_masks = independent
                    .iter()
                    .map(|[first, second]| {
                        [
                            CompactChallengeField::ZERO,
                            *first,
                            *second,
                            -(*first + *second),
                        ]
                    })
                    .collect();
                let material = CompactCfwMaskMaterial::from_canonical_messages(
                    geometry,
                    inner_masks,
                    zero_outer_masks(geometry),
                )
                .expect("canonical selected inner masks");
                let mut state = CompactCfwScalarProverState::begin(
                    geometry,
                    material,
                    CompactChallengeField::ZERO,
                    vec![CompactChallengeField::ZERO; geometry.sumcheck_round_count()],
                )
                .expect("selected real scalar state");
                for challenge in &challenges {
                    state
                        .accept_round_polynomial(
                            [CompactChallengeField::ZERO; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH],
                        )
                        .expect("zero constraint round");
                    state
                        .bind_round_challenge(*challenge)
                        .expect("selected challenge");
                }
                let actual = state
                    .finish([CompactChallengeField::ZERO; COMPACT_CFW_MATRIX_COUNT])
                    .expect("selected terminal finish")
                    .final_values();
                let expected = apply_cfw_inner_terminal_view(&independent, &challenges)
                    .expect("independent selected terminal projection");
                assert_eq!(
                    actual, expected,
                    "private coordinate {selected_private_coordinate:?}"
                );
            }
        }
    }

    #[test]
    fn conditional_cfw_image_is_an_exact_right_inverse_after_every_prefix() {
        let certificate = derive_selected_compact_masking_coefficient_map_certificate()
            .expect("selected coefficient maps derive");
        let map_ordinal = certificate
            .maps()
            .iter()
            .position(|map| {
                map.coordinate.role == CompactMaskingViewRole::Sumcheck
                    && map.coordinate.epoch == 0
                    && map.coordinate.coordinate == 1
            })
            .expect("the CFW outer map exists");
        let map = &certificate.maps()[map_ordinal];
        let CompactCoefficientProjection::CfwOuterTranscript { round_count } = map.projection
        else {
            panic!("the selected map is the CFW outer transcript")
        };
        let round_count = usize::try_from(round_count).expect("round count fits");
        let challenges = (0..round_count)
            .map(|ordinal| CompactChallengeField::from_u64(3 + 2 * ordinal as u64))
            .collect::<Vec<_>>();
        let private = (0..map.private_coordinate_count)
            .map(|ordinal| CompactChallengeField::from_u64(101 + ordinal))
            .collect::<Vec<_>>();
        let masks = private
            .chunks_exact(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
            .map(|mask| mask.try_into().expect("one complete CFW mask"))
            .collect::<Vec<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>>();
        let actual = apply_cfw_outer_mask_view(&masks, &challenges).expect("actual CFW view");
        let mut view = vec![actual.auxiliary_target];
        view.extend(actual.round_polynomials.into_iter().flatten());
        view.extend(actual.outer_evaluations);
        let mut first = 0_usize;
        let block_shapes = core::iter::once((1_usize, 1_usize))
            .chain((0..round_count).map(|_| {
                (
                    COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH,
                    COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH - 1,
                )
            }))
            .chain(core::iter::once((round_count, round_count - 1)));
        for (step_ordinal, (output_count, rank)) in block_shapes.enumerate() {
            let known_challenge_count = if step_ordinal == 0 {
                0
            } else if step_ordinal <= round_count {
                step_ordinal - 1
            } else {
                round_count
            };
            let request = certificate
                .prepare_conditional_image(
                    map_ordinal,
                    u32::try_from(step_ordinal).expect("step ordinal fits"),
                    u64::try_from(first).expect("first output fits"),
                    u64::try_from(output_count).expect("output count fits"),
                    u64::try_from(rank).expect("rank fits"),
                    [0x51; 64],
                    &view[..first],
                    CompactConditionalImageRuntime::CfwOuter {
                        round_challenges: &challenges[..known_challenge_count],
                    },
                )
                .expect("the exact conditional CFW image derives");
            let independent = request
                .expansion
                .independent_coordinates(&view[first..first + output_count]);
            let expanded = certificate
                .execute_conditional_image(
                    &request,
                    u32::try_from(step_ordinal).expect("step ordinal fits"),
                    [0x51; 64],
                    &independent,
                )
                .expect("right inverse expands");
            assert_eq!(expanded, view[first..first + output_count]);
            first += output_count;
        }
        assert_eq!(first, view.len());
    }

    #[test]
    fn reed_solomon_conditional_image_injects_disjoint_partial_and_full_overlap_coordinates() {
        let certificate = derive_selected_compact_masking_coefficient_map_certificate()
            .expect("selected coefficient maps derive");
        let map_ordinal = certificate
            .maps()
            .iter()
            .position(|map| {
                map.coordinate.role == CompactMaskingViewRole::Source
                    && map.coordinate.epoch == 1
                    && map.coordinate.batch_ordinal == 0
            })
            .expect("the first WHIR source map exists");
        let map = &certificate.maps()[map_ordinal];
        let CompactCoefficientProjection::FoldedReedSolomonSource { lane_count, .. } =
            map.projection
        else {
            panic!("the selected map is a folded Reed-Solomon source")
        };
        let lane_count = usize::try_from(lane_count).expect("lane count fits");

        let disjoint_positions = [3_u64, 9];
        let disjoint_coordinate_count = lane_count * disjoint_positions.len();
        let disjoint_request = certificate
            .prepare_conditional_image(
                map_ordinal,
                40,
                0,
                u64::try_from(disjoint_coordinate_count).expect("output count fits"),
                u64::try_from(disjoint_coordinate_count).expect("rank fits"),
                [0x81; 64],
                &[],
                CompactConditionalImageRuntime::ReedSolomonQueries {
                    preceding_query_positions: &[],
                    query_positions: &disjoint_positions,
                },
            )
            .expect("the disjoint image derives");
        let disjoint_coordinates = (0..disjoint_coordinate_count)
            .map(|coordinate| CompactChallengeField::from_u64(1_000 + coordinate as u64))
            .collect::<Vec<_>>();
        assert_eq!(
            certificate
                .execute_conditional_image(
                    &disjoint_request,
                    40,
                    [0x81; 64],
                    &disjoint_coordinates,
                )
                .expect("disjoint coordinates inject"),
            disjoint_coordinates,
        );

        let preceding_positions = [3_u64, 9];
        let preceding_values = (0..lane_count * preceding_positions.len())
            .map(|coordinate| CompactChallengeField::from_u64(2_000 + coordinate as u64))
            .collect::<Vec<_>>();
        let partially_overlapping_positions = [9_u64, 11, 17];
        let partial_rank = lane_count * 2;
        assert_eq!(
            certificate.prepare_conditional_image(
                map_ordinal,
                41,
                u64::try_from(preceding_values.len()).expect("prefix count fits"),
                u64::try_from(lane_count * partially_overlapping_positions.len())
                    .expect("output count fits"),
                u64::try_from(partial_rank + 1).expect("wrong rank fits"),
                [0x82; 64],
                &preceding_values,
                CompactConditionalImageRuntime::ReedSolomonQueries {
                    preceding_query_positions: &preceding_positions,
                    query_positions: &partially_overlapping_positions,
                },
            ),
            Err(CompactMaskingCoefficientMapError::InvalidConditionalImage),
        );
        let partial_request = certificate
            .prepare_conditional_image(
                map_ordinal,
                41,
                u64::try_from(preceding_values.len()).expect("prefix count fits"),
                u64::try_from(lane_count * partially_overlapping_positions.len())
                    .expect("output count fits"),
                u64::try_from(partial_rank).expect("rank fits"),
                [0x82; 64],
                &preceding_values,
                CompactConditionalImageRuntime::ReedSolomonQueries {
                    preceding_query_positions: &preceding_positions,
                    query_positions: &partially_overlapping_positions,
                },
            )
            .expect("the partial-overlap image derives");
        let partial_coordinates = (0..partial_rank)
            .map(|coordinate| CompactChallengeField::from_u64(3_000 + coordinate as u64))
            .collect::<Vec<_>>();
        let mut expected_partial = preceding_values[lane_count..2 * lane_count].to_vec();
        expected_partial.extend_from_slice(&partial_coordinates);
        assert_eq!(
            certificate
                .execute_conditional_image(&partial_request, 41, [0x82; 64], &partial_coordinates,)
                .expect("partial-overlap coordinates inject"),
            expected_partial,
        );

        let full_overlap_request = certificate
            .prepare_conditional_image(
                map_ordinal,
                42,
                u64::try_from(preceding_values.len()).expect("prefix count fits"),
                u64::try_from(preceding_values.len()).expect("output count fits"),
                0,
                [0x83; 64],
                &preceding_values,
                CompactConditionalImageRuntime::ReedSolomonQueries {
                    preceding_query_positions: &preceding_positions,
                    query_positions: &preceding_positions,
                },
            )
            .expect("the full-overlap image derives");
        assert_eq!(
            certificate
                .execute_conditional_image(&full_overlap_request, 42, [0x83; 64], &[])
                .expect("full overlap copies retained values"),
            preceding_values,
        );
    }

    #[test]
    fn shared_reed_solomon_opening_preserves_full_duplicate_output_at_zero_rank() {
        let certificate = derive_selected_compact_masking_coefficient_map_certificate()
            .expect("selected coefficient maps derive");
        let map_ordinal = certificate
            .maps()
            .iter()
            .position(|map| {
                map.coordinate.role == CompactMaskingViewRole::CarriedMask
                    && map.coordinate.epoch == 1
                    && map.coordinate.batch_ordinal == 0
                    && matches!(
                        map.projection,
                        CompactCoefficientProjection::CarriedMaskReedSolomon {
                            contract_role_tag: 1,
                            lane_count: 2,
                            ..
                        }
                    )
            })
            .expect("the shared cross-epoch code exists");
        let map = &certificate.maps()[map_ordinal];
        let CompactCoefficientProjection::CarriedMaskReedSolomon {
            lane_count,
            message_length_per_lane,
            randomness_length_per_lane,
            domain_size,
            ..
        } = map.projection
        else {
            unreachable!()
        };
        let lane_dimension = message_length_per_lane + randomness_length_per_lane;
        let coefficients = (0..lane_count * lane_dimension)
            .map(|ordinal| CompactChallengeField::from_u64(71 + ordinal))
            .collect::<Vec<_>>();
        let positions = [1_u64, 7, 19];
        let generator = CompactChallengeField::two_adic_generator(
            usize::try_from(domain_size.ilog2()).expect("log domain fits"),
        );
        let first_output = positions
            .iter()
            .flat_map(|position| {
                coefficients
                    .chunks_exact(usize::try_from(lane_dimension).expect("lane dimension fits"))
                    .map(move |lane| apply_reed_solomon_query(generator, *position, lane))
            })
            .collect::<Vec<_>>();
        let request = certificate
            .prepare_conditional_image(
                map_ordinal,
                33,
                u64::try_from(first_output.len()).expect("prefix length fits"),
                u64::try_from(first_output.len()).expect("output length fits"),
                0,
                [0x91; 64],
                &first_output,
                CompactConditionalImageRuntime::ReedSolomonQueries {
                    preceding_query_positions: &positions,
                    query_positions: &positions,
                },
            )
            .expect("the duplicate shared opening has a zero-dimensional image");
        assert_eq!(
            certificate
                .execute_conditional_image(&request, 33, [0x91; 64], &[])
                .expect("zero coordinates reproduce the retained opening"),
            first_output,
        );
    }

    #[test]
    fn conditional_image_rejects_wrong_rank_and_transcript_replay() {
        let certificate = derive_selected_compact_masking_coefficient_map_certificate()
            .expect("selected coefficient maps derive");
        let map_ordinal = certificate
            .maps()
            .iter()
            .position(|map| map.coordinate.role == CompactMaskingViewRole::ExplicitPoint)
            .expect("explicit-point map exists");
        assert_eq!(
            certificate.prepare_conditional_image(
                map_ordinal,
                7,
                0,
                3,
                3,
                [0x31; 64],
                &[],
                CompactConditionalImageRuntime::CrossEpochExplicitPoint,
            ),
            Err(CompactMaskingCoefficientMapError::InvalidConditionalImage),
        );
        let request = certificate
            .prepare_conditional_image(
                map_ordinal,
                7,
                0,
                3,
                2,
                [0x31; 64],
                &[],
                CompactConditionalImageRuntime::CrossEpochExplicitPoint,
            )
            .expect("the exact rank-two image derives");
        assert_eq!(
            request.expansion,
            CompactConditionalImageExpansion::Dense {
                offset: vec![CompactChallengeField::ZERO; 3],
                basis: vec![
                    vec![
                        CompactChallengeField::ONE,
                        CompactChallengeField::ZERO,
                        CompactChallengeField::ONE,
                    ],
                    vec![
                        CompactChallengeField::ZERO,
                        CompactChallengeField::ONE,
                        -CompactChallengeField::ONE,
                    ],
                ],
                pivot_output_coordinates: vec![0, 1],
            }
        );
        let first = CompactChallengeField::from_u64(17);
        let second = CompactChallengeField::from_u64(29);
        assert_eq!(
            certificate
                .execute_conditional_image(&request, 7, [0x31; 64], &[first, second],)
                .expect("the canonical rank-two coordinates expand"),
            vec![first, second, first - second],
        );
        certificate
            .verify_conditional_image_output(
                &request,
                7,
                [0x31; 64],
                &[first, second, first - second],
            )
            .expect("the real rank-two disclosure belongs to the compiled image");
        assert_eq!(
            certificate.verify_conditional_image_output(
                &request,
                7,
                [0x31; 64],
                &[first, second, first - second + CompactChallengeField::ONE],
            ),
            Err(CompactMaskingCoefficientMapError::InvalidConditionalImage),
        );
        assert_eq!(
            certificate.verify_conditional_image_output(&request, 7, [0x31; 64], &[first, second],),
            Err(CompactMaskingCoefficientMapError::WrongConditionalImageRequest),
        );
        assert_eq!(
            certificate.verify_conditional_image_output(
                &request,
                7,
                [0x32; 64],
                &[first, second, first - second],
            ),
            Err(CompactMaskingCoefficientMapError::WrongConditionalImageRequest),
        );
        assert_eq!(
            certificate.execute_conditional_image(
                &request,
                7,
                [0x32; 64],
                &[CompactChallengeField::ZERO; 2],
            ),
            Err(CompactMaskingCoefficientMapError::WrongConditionalImageRequest),
        );
    }

    #[test]
    fn revealed_final_source_mirror_queries_one_folded_polynomial() {
        let certificate = derive_selected_compact_masking_coefficient_map_certificate()
            .expect("selected coefficient maps derive");
        let map_ordinal = certificate
            .maps()
            .iter()
            .position(|map| {
                map.coordinate.role == CompactMaskingViewRole::Mirror
                    && map.coordinate.epoch == 1
                    && map.coordinate.coordinate == 0
                    && matches!(
                        map.projection,
                        CompactCoefficientProjection::AffineMirror {
                            carried_map_ordinal,
                            ..
                        } if matches!(
                            certificate.maps()[carried_map_ordinal].projection,
                            CompactCoefficientProjection::LimbFold { .. }
                        )
                    )
            })
            .expect("the pre-challenge final-source mirror exists");
        let map = &certificate.maps()[map_ordinal];
        let source = certificate
            .maps()
            .iter()
            .find(|candidate| {
                candidate.coordinate.role == CompactMaskingViewRole::Source
                    && candidate.coordinate.epoch == map.coordinate.epoch
                    && candidate.coordinate.batch_ordinal == map.coordinate.batch_ordinal
            })
            .expect("the folded source code exists");
        let CompactCoefficientProjection::FoldedReedSolomonSource {
            lane_count,
            domain_size,
            ..
        } = source.projection
        else {
            unreachable!()
        };
        assert!(
            lane_count > 1,
            "the source code is folded across many limbs"
        );

        let coefficients = (0..map.view_coordinate_count)
            .map(|ordinal| CompactChallengeField::from_u64(47 + ordinal))
            .collect::<Vec<_>>();
        let query_positions = [1_u64, 7, 19];
        let generator = CompactChallengeField::two_adic_generator(
            usize::try_from(domain_size.ilog2()).expect("log domain fits"),
        );
        let expected = query_positions
            .iter()
            .map(|position| apply_reed_solomon_query(generator, *position, &coefficients))
            .collect::<Vec<_>>();
        let request = certificate
            .prepare_conditional_image(
                map_ordinal,
                9,
                0,
                u64::try_from(query_positions.len()).expect("query count fits"),
                0,
                [0x71; 64],
                &[],
                CompactConditionalImageRuntime::AffineMirrorQueries {
                    query_positions: &query_positions,
                    retained_mirror_coefficients: &coefficients,
                },
            )
            .expect("the final-source query image derives");
        assert_eq!(
            certificate
                .execute_conditional_image(&request, 9, [0x71; 64], &[])
                .expect("the retained folded polynomial evaluates"),
            expected,
        );
    }

    #[test]
    fn revealed_affine_mirror_queries_are_zero_rank_deterministic_images() {
        let certificate = derive_selected_compact_masking_coefficient_map_certificate()
            .expect("selected coefficient maps derive");
        let map_ordinal = certificate
            .maps()
            .iter()
            .position(|map| {
                map.coordinate.role == CompactMaskingViewRole::Mirror
                    && map.coordinate.epoch == 1
                    && map.coordinate.coordinate == 1
                    && matches!(
                        map.projection,
                        CompactCoefficientProjection::AffineMirror {
                            carried_map_ordinal,
                            ..
                        } if matches!(
                            certificate.maps()[carried_map_ordinal].projection,
                            CompactCoefficientProjection::CarriedMaskReedSolomon {
                                lane_count,
                                maximum_query_count,
                                domain_size,
                                ..
                            } if lane_count > 1 && maximum_query_count >= 3 && domain_size > 19
                        )
                    )
            })
            .expect("one multi-lane affine mask mirror exists");
        let map = &certificate.maps()[map_ordinal];
        let CompactCoefficientProjection::AffineMirror {
            carried_map_ordinal,
            ..
        } = map.projection
        else {
            unreachable!()
        };
        let CompactCoefficientProjection::CarriedMaskReedSolomon {
            lane_count,
            message_length_per_lane,
            randomness_length_per_lane,
            ..
        } = certificate.maps()[carried_map_ordinal].projection
        else {
            unreachable!()
        };
        let lane_count = usize::try_from(lane_count).expect("lane count fits");
        let lane_dimension = usize::try_from(message_length_per_lane + randomness_length_per_lane)
            .expect("lane dimension fits");
        let mut coefficients = vec![
            CompactChallengeField::ZERO;
            usize::try_from(map.view_coordinate_count)
                .expect("mirror coordinate count fits")
        ];
        let expected_query_values = (0..lane_count)
            .map(|lane_ordinal| CompactChallengeField::from_u64(47 + lane_ordinal as u64))
            .collect::<Vec<_>>();
        for (lane_ordinal, lane) in coefficients.chunks_exact_mut(lane_dimension).enumerate() {
            lane[0] = expected_query_values[lane_ordinal];
        }
        let query_positions = [1_u64, 7, 19];
        let request = certificate
            .prepare_conditional_image(
                map_ordinal,
                9,
                0,
                u64::try_from(query_positions.len() * lane_count).expect("query count fits"),
                0,
                [0x72; 64],
                &[],
                CompactConditionalImageRuntime::AffineMirrorQueries {
                    query_positions: &query_positions,
                    retained_mirror_coefficients: &coefficients,
                },
            )
            .expect("zero-rank query image derives");
        let output = certificate
            .execute_conditional_image(&request, 9, [0x72; 64], &[])
            .expect("zero independent coordinates expand deterministically");
        assert_eq!(
            output,
            query_positions
                .iter()
                .flat_map(|_| expected_query_values.iter().copied())
                .collect::<Vec<_>>()
        );
        assert_eq!(request.independent_coordinate_count(), 0);
    }
}
