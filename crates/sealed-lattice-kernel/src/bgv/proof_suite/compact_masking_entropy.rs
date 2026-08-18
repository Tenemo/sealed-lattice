//! Joint conditional entropy for the selected compact masking system.
//!
//! This owner replays disclosures in verifier chronology. Each step records
//! only the rank added modulo all earlier views of the same private source.
//! The certificate is derived from the decoded production contract, the
//! executable coefficient-map certificate, and the actual transcript
//! challenges and query coordinates; no transported rank or count is trusted.

use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;

use super::compact_cfw::{
    COMPACT_CFW_MATRIX_COUNT, COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, CompactChallengeField,
    compact_cfw_final_challenge_is_allowed, compact_challenge_from_production,
};
use super::compact_masking_coefficient_maps::{
    CompactCoefficientProjection, CompactCommitmentQuerySource, CompactConditionalImageRequest,
    CompactConditionalImageRuntime, CompactConstructionCommitmentOwnership,
    CompactMaskingCoefficientMapCertificate, CompactMaskingViewRole, CompactSurjectivityWitness,
    apply_cfw_outer_mask_view, reed_solomon_query_coefficient,
};
#[cfg(test)]
use super::compact_masking_coefficient_maps::{
    CompactCoefficientToViewMap, apply_cfw_inner_terminal_view, apply_whir_sumcheck_mask_view,
};
use super::compact_masking_prefix::{CompactMaskingAttemptIdentity, CompactMaskingSemanticPrefix};
use super::compact_masking_public_covector::{
    CompactFactorOneCarriedCovector, CompactFactorOnePublicCovectorAuthority,
    CompactFactorOnePublicCovectorDerivation, CompactFactorOnePublicCovectorPoll,
};
use super::compact_proof_contract::{
    CompactPublicKeyVerifierInputs, CompactResponseComponentRoleContract,
    CompactVerifierMoveContract, CompactWhirEpochContract, CompactWhirFoldContract,
};
use super::compact_response_merkle::{
    CompactResponseComponentGeometry, CompactResponseLeafValueKind, CompactResponseMerkleGeometry,
    CompactResponseQuerySelection,
};
use super::fixed_uniform_verifier_message::DecodedFixedUniformVerifierMessage;
use crate::hashing::hash_framed_parts_512;

#[cfg(test)]
const DISCLOSURE_DIGEST_DOMAIN: &str =
    "sealed-lattice/proof/compact-masking-entropy-disclosures/v1";
#[cfg(test)]
const CONTRACT_BINDING_DOMAIN: &str = "sealed-lattice/proof/compact-masking-entropy-contract/v1";
const LIVE_PREFIX_BINDING_DOMAIN: &str = "sealed-lattice/proof/compact-masking-live-prefix/v1";
const WHIR_FOLD_COUNT_PER_EPOCH: usize = 4;
const CFW_OUTER_MASK_MESSAGE_LENGTH_U64: u64 = COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH as u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactMaskingQuerySet {
    logical_verifier_move_ordinal: u32,
    distinct_query_group_ordinal: u32,
    indices: Vec<u64>,
}

impl CompactMaskingQuerySet {
    #[cfg(test)]
    pub(crate) fn new(
        logical_verifier_move_ordinal: u32,
        distinct_query_group_ordinal: u32,
        indices: Vec<u64>,
    ) -> Self {
        Self {
            logical_verifier_move_ordinal,
            distinct_query_group_ordinal,
            indices,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactMaskingSumcheckChallenges {
    epoch: u8,
    batch_ordinal: u8,
    challenges: Vec<CompactChallengeField>,
}

impl CompactMaskingSumcheckChallenges {
    #[cfg(test)]
    pub(crate) fn new(
        epoch: u8,
        batch_ordinal: u8,
        challenges: Vec<CompactChallengeField>,
    ) -> Self {
        Self {
            epoch,
            batch_ordinal,
            challenges,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactBaseFreshClaimCoefficients {
    epoch: u8,
    coefficients: Vec<CompactChallengeField>,
}

pub(crate) struct CompactVerifiedBaseRevealMasking {
    identity: CompactMaskingAttemptIdentity,
    claim: CompactBaseFreshClaimCoefficients,
    completed_messages: Box<[DecodedFixedUniformVerifierMessage]>,
}

pub(crate) struct CompactVerifiedBaseMaskingPrefix {
    identity: CompactMaskingAttemptIdentity,
    claim: CompactBaseFreshClaimCoefficients,
    completed_messages: Box<[DecodedFixedUniformVerifierMessage]>,
}

/// Public covectors independently replayed for a selected WHIR base claim at
/// its exact authenticated transcript prefix.
pub(crate) struct CompactVerifiedWhirBaseCovector {
    source: Vec<CompactChallengeField>,
    mask_groups: Vec<Vec<Vec<CompactChallengeField>>>,
}

/// One canonical extension-field leaf selected by a compact WHIR verifier
/// query. Its committed value may be evaluated before a shared root's later
/// last-use opening; the entropy owner independently maps the response and
/// leaf ordinals back to their compiler-derived consumers.
pub(crate) struct CompactMaskingQueryLeaf {
    response_ordinal: u32,
    leaf_ordinal: u64,
    values: Vec<CompactChallengeField>,
}

impl CompactMaskingQueryLeaf {
    pub(crate) fn new(
        response_ordinal: u32,
        leaf_ordinal: u64,
        values: Vec<CompactChallengeField>,
    ) -> Result<Self, CompactMaskingEntropyError> {
        if values.is_empty() {
            return Err(CompactMaskingEntropyError::MissingTranscriptInput);
        }
        Ok(Self {
            response_ordinal,
            leaf_ordinal,
            values,
        })
    }

    #[cfg(test)]
    pub(crate) const fn response_ordinal(&self) -> u32 {
        self.response_ordinal
    }

    #[cfg(test)]
    pub(crate) const fn leaf_ordinal(&self) -> u64 {
        self.leaf_ordinal
    }
}

impl CompactVerifiedWhirBaseCovector {
    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<CompactChallengeField>,
        Vec<Vec<Vec<CompactChallengeField>>>,
    ) {
        (self.source, self.mask_groups)
    }
}

impl CompactBaseFreshClaimCoefficients {
    #[cfg(test)]
    pub(crate) const fn epoch(&self) -> u8 {
        self.epoch
    }

    #[cfg(test)]
    pub(crate) fn coefficients(&self) -> &[CompactChallengeField] {
        &self.coefficients
    }

    #[cfg(test)]
    fn new(epoch: u8, coefficients: Vec<CompactChallengeField>) -> Self {
        Self {
            epoch,
            coefficients,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_carried_covector(
        covector: &super::compact_masking_public_covector::CompactFactorOneCarriedCovector,
    ) -> Result<Self, CompactMaskingEntropyError> {
        let epoch = covector
            .epoch()
            .ok_or(CompactMaskingEntropyError::InvalidCoefficientVector)?;
        let coefficients = covector
            .coefficients()
            .ok_or(CompactMaskingEntropyError::InvalidCoefficientVector)?
            .to_vec();
        Ok(Self {
            epoch,
            coefficients,
        })
    }
}

impl CompactVerifiedBaseRevealMasking {
    fn authorizes_final_query(
        &self,
        identity: CompactMaskingAttemptIdentity,
        epoch: u8,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
    ) -> bool {
        self.identity == identity
            && self.claim.epoch == epoch
            && self.completed_messages.len() < completed_messages.len()
            && completed_messages.starts_with(&self.completed_messages)
    }
}

impl CompactVerifiedBaseMaskingPrefix {
    fn authorizes_replay(
        &self,
        identity: CompactMaskingAttemptIdentity,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
    ) -> bool {
        self.identity == identity
            && self.completed_messages.len() <= completed_messages.len()
            && completed_messages.starts_with(&self.completed_messages)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactMaskingEntropyTranscript {
    cfw_constraint_combining_challenge: Option<CompactChallengeField>,
    cfw_equality_point: Vec<CompactChallengeField>,
    cfw_round_challenges: Vec<CompactChallengeField>,
    sumcheck_challenges: Vec<CompactMaskingSumcheckChallenges>,
    query_sets: Vec<CompactMaskingQuerySet>,
    base_fresh_claims: Vec<CompactBaseFreshClaimCoefficients>,
}

impl CompactMaskingEntropyTranscript {
    #[cfg(test)]
    pub(crate) fn new(
        cfw_constraint_combining_challenge: Option<CompactChallengeField>,
        cfw_equality_point: Vec<CompactChallengeField>,
        cfw_round_challenges: Vec<CompactChallengeField>,
        sumcheck_challenges: Vec<CompactMaskingSumcheckChallenges>,
        query_sets: Vec<CompactMaskingQuerySet>,
        base_fresh_claims: Vec<CompactBaseFreshClaimCoefficients>,
    ) -> Self {
        Self {
            cfw_constraint_combining_challenge,
            cfw_equality_point,
            cfw_round_challenges,
            sumcheck_challenges,
            query_sets,
            base_fresh_claims,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactMaskingDisclosureKind {
    CrossEpochExplicitPoint,
    CfwOuterAuxiliary,
    CfwOuterRound {
        round_ordinal: u32,
    },
    CfwOuterEvaluations,
    CfwInnerTerminal,
    WhirSumcheckAuxiliary {
        epoch: u8,
        batch_ordinal: u8,
    },
    WhirSumcheckRound {
        epoch: u8,
        batch_ordinal: u8,
        round_ordinal: u32,
    },
    SourceQueries {
        epoch: u8,
        source_ordinal: u8,
    },
    CarriedMaskQueries {
        epoch: u8,
        group_ordinal: u8,
        contract_role_tag: u8,
    },
    BaseFreshClaim {
        epoch: u8,
    },
    BaseBlindedSourceMessage {
        epoch: u8,
    },
    BaseBlindedSourceRandomness {
        epoch: u8,
    },
    BaseBlindedMaskGroup {
        epoch: u8,
        group_ordinal: u8,
    },
    FreshSourceQueries {
        epoch: u8,
    },
    FreshMaskQueries {
        epoch: u8,
        group_ordinal: u8,
    },
}

impl CompactMaskingDisclosureKind {
    #[cfg(test)]
    pub(crate) const fn reveal_epoch(self) -> Option<u8> {
        match self {
            Self::BaseBlindedSourceMessage { epoch }
            | Self::BaseBlindedSourceRandomness { epoch }
            | Self::BaseBlindedMaskGroup { epoch, .. } => Some(epoch),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactMaskingEntropyStep {
    ordinal: u32,
    verifier_move_ordinal: u32,
    kind: CompactMaskingDisclosureKind,
    output_coordinate_count: u64,
    image: CompactMaskingDisclosureImage,
    conditional_rank: u64,
    cumulative_rank: u64,
    residual_entropy_dimension: u64,
}

/// Checked image of one affine disclosure after conditioning on its source's
/// preceding rows. Full-coordinate images may be sampled uniformly. A
/// constrained image names the canonical coefficient-map block that owns its
/// row space; a simulator must sample that image, never independent outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactMaskingDisclosureImage {
    FullCoordinateSpace,
    CoefficientMapImage {
        map_ordinal: usize,
        first_output_coordinate: u64,
    },
    LinearClaimFiber {
        pivot_output_coordinate: u64,
    },
}

/// Opaque, authority-minted request for sampling one checked conditional
/// image. The ideal oracle receives no private row ledger or mutable map; it
/// can only answer the exact step and transcript prefix named here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactMaskingIdealImageRequest {
    attempt_identity: CompactMaskingAttemptIdentity,
    step_ordinal: u32,
    verifier_move_ordinal: u32,
    output_coordinate_count: u64,
    independent_coordinate_count: u64,
    image: CompactMaskingDisclosureImage,
    transcript_prefix_binding: [u8; 64],
}

impl CompactMaskingIdealImageRequest {
    #[cfg(test)]
    pub(crate) const fn attempt_identity(&self) -> CompactMaskingAttemptIdentity {
        self.attempt_identity
    }

    #[cfg(test)]
    pub(crate) const fn step_ordinal(&self) -> u32 {
        self.step_ordinal
    }

    #[cfg(test)]
    pub(crate) const fn verifier_move_ordinal(&self) -> u32 {
        self.verifier_move_ordinal
    }

    #[cfg(test)]
    pub(crate) const fn output_coordinate_count(&self) -> u64 {
        self.output_coordinate_count
    }

    #[cfg(test)]
    pub(crate) const fn independent_coordinate_count(&self) -> u64 {
        self.independent_coordinate_count
    }

    #[cfg(test)]
    pub(crate) const fn image(&self) -> CompactMaskingDisclosureImage {
        self.image
    }
}

impl CompactMaskingEntropyStep {
    #[cfg(test)]
    pub(crate) const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    #[cfg(test)]
    pub(crate) const fn verifier_move_ordinal(&self) -> u32 {
        self.verifier_move_ordinal
    }

    pub(crate) const fn kind(&self) -> CompactMaskingDisclosureKind {
        self.kind
    }

    pub(crate) const fn output_coordinate_count(&self) -> u64 {
        self.output_coordinate_count
    }

    #[cfg(test)]
    pub(crate) const fn image(&self) -> CompactMaskingDisclosureImage {
        self.image
    }

    pub(crate) const fn conditional_rank(&self) -> u64 {
        self.conditional_rank
    }

    #[cfg(test)]
    pub(crate) const fn cumulative_rank(&self) -> u64 {
        self.cumulative_rank
    }

    #[cfg(test)]
    pub(crate) const fn residual_entropy_dimension(&self) -> u64 {
        self.residual_entropy_dimension
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactMaskingEntropyCertificate {
    steps: Vec<CompactMaskingEntropyStep>,
    private_coordinate_count: u64,
    joint_disclosure_rank: u64,
    residual_conditional_entropy_dimension: u64,
    shared_cross_epoch_query_overlap: u64,
    disclosure_digest: [u8; 64],
    contract_binding: [u8; 64],
    coefficient_map_binding: [u8; 64],
}

#[cfg(test)]
impl CompactMaskingEntropyCertificate {
    pub(crate) fn steps(&self) -> &[CompactMaskingEntropyStep] {
        &self.steps
    }

    pub(crate) const fn private_coordinate_count(&self) -> u64 {
        self.private_coordinate_count
    }

    pub(crate) const fn joint_disclosure_rank(&self) -> u64 {
        self.joint_disclosure_rank
    }

    pub(crate) const fn residual_conditional_entropy_dimension(&self) -> u64 {
        self.residual_conditional_entropy_dimension
    }

    pub(crate) const fn shared_cross_epoch_query_overlap(&self) -> u64 {
        self.shared_cross_epoch_query_overlap
    }

    pub(crate) const fn disclosure_digest(&self) -> [u8; 64] {
        self.disclosure_digest
    }

    pub(crate) const fn contract_binding(&self) -> [u8; 64] {
        self.contract_binding
    }

    pub(crate) fn check(
        &self,
        coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    ) -> Result<(), CompactMaskingEntropyError> {
        coefficient_maps
            .check()
            .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientMap)?;
        let summed_rank = self
            .steps
            .iter()
            .try_fold(0_u64, |rank, step| checked_add(rank, step.conditional_rank))?;
        if self.coefficient_map_binding != coefficient_maps.certificate_digest()
            || self.disclosure_digest != hash_steps(&self.steps)
            || summed_rank != self.joint_disclosure_rank
            || self
                .private_coordinate_count
                .checked_sub(self.joint_disclosure_rank)
                != Some(self.residual_conditional_entropy_dimension)
        {
            return Err(CompactMaskingEntropyError::CertificateMismatch);
        }
        Ok(())
    }

    pub(crate) fn begin_disclosures(
        &self,
        identity: CompactMaskingAttemptIdentity,
    ) -> CompactMaskingEntropyCursor {
        CompactMaskingEntropyCursor {
            identity,
            contract_binding: self.contract_binding,
            disclosure_digest: self.disclosure_digest,
            next_step_ordinal: 0,
            cumulative_rank: 0,
        }
    }

    pub(crate) fn verify_simulator_disclosure(
        &self,
        cursor: &mut CompactMaskingEntropyCursor,
        identity: CompactMaskingAttemptIdentity,
        step: &CompactMaskingEntropyStep,
    ) -> Result<(), CompactMaskingEntropyError> {
        if cursor.identity != identity {
            return Err(CompactMaskingEntropyError::AttemptIdentityMismatch);
        }
        if cursor.contract_binding != self.contract_binding
            || cursor.disclosure_digest != self.disclosure_digest
        {
            return Err(CompactMaskingEntropyError::CertificateMismatch);
        }
        let expected = self
            .steps
            .get(cursor.next_step_ordinal)
            .ok_or(CompactMaskingEntropyError::DisclosureOutOfOrder)?;
        if step != expected
            || step.cumulative_rank != cursor.cumulative_rank + step.conditional_rank
        {
            return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
        }
        cursor.cumulative_rank = step.cumulative_rank;
        cursor.next_step_ordinal += 1;
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactMaskingEntropyCursor {
    identity: CompactMaskingAttemptIdentity,
    contract_binding: [u8; 64],
    disclosure_digest: [u8; 64],
    next_step_ordinal: usize,
    cumulative_rank: u64,
}

#[cfg(test)]
impl CompactMaskingEntropyCursor {
    pub(crate) fn finish(
        self,
        certificate: &CompactMaskingEntropyCertificate,
        identity: CompactMaskingAttemptIdentity,
    ) -> Result<(), CompactMaskingEntropyError> {
        if self.identity != identity {
            return Err(CompactMaskingEntropyError::AttemptIdentityMismatch);
        }
        if self.contract_binding != certificate.contract_binding
            || self.disclosure_digest != certificate.disclosure_digest
        {
            return Err(CompactMaskingEntropyError::CertificateMismatch);
        }
        if self.next_step_ordinal != certificate.steps.len()
            || self.cumulative_rank != certificate.joint_disclosure_rank
        {
            return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactBaseFreshClaimRequirement {
    epoch: u8,
    coefficient_count: u64,
}

impl CompactBaseFreshClaimRequirement {
    #[cfg(test)]
    pub(crate) const fn epoch(self) -> u8 {
        self.epoch
    }

    #[cfg(test)]
    pub(crate) const fn coefficient_count(self) -> u64 {
        self.coefficient_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactMaskingEntropyAuthorityPhase {
    AwaitingResponse,
    AwaitingVerifierMessage,
}

/// Streaming owner for adaptive verifier chronology. It exposes only the
/// response image before a message is chosen, then conditions the query
/// openings selected by the decoded message after that message is ingested.
pub(crate) struct CompactMaskingEntropyAuthority<'contract> {
    inputs: CompactPublicKeyVerifierInputs<'contract>,
    coefficient_maps: &'contract CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    next_move_ordinal: usize,
    phase: CompactMaskingEntropyAuthorityPhase,
    transcript: CompactMaskingEntropyTranscript,
    sources: Vec<SourceState>,
    steps: Vec<CompactMaskingEntropyStep>,
    response_range: std::ops::Range<usize>,
    message_range: std::ops::Range<usize>,
}

impl<'contract> CompactMaskingEntropyAuthority<'contract> {
    pub(crate) fn begin(
        inputs: CompactPublicKeyVerifierInputs<'contract>,
        coefficient_maps: &'contract CompactMaskingCoefficientMapCertificate,
        identity: CompactMaskingAttemptIdentity,
    ) -> Result<Self, CompactMaskingEntropyError> {
        coefficient_maps
            .check()
            .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientMap)?;
        if inputs
            .canonical_source_hash()
            .map_err(|_| CompactMaskingEntropyError::InvalidContract)?
            .into_bytes()
            != coefficient_maps.certificate_digest()
        {
            return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
        }
        validate_rank_map_coverage(coefficient_maps)?;
        let sources = derive_private_sources(&inputs)?;
        Ok(Self {
            inputs,
            coefficient_maps,
            identity,
            next_move_ordinal: 0,
            phase: CompactMaskingEntropyAuthorityPhase::AwaitingResponse,
            transcript: CompactMaskingEntropyTranscript {
                cfw_constraint_combining_challenge: None,
                cfw_equality_point: Vec::new(),
                cfw_round_challenges: Vec::new(),
                sumcheck_challenges: Vec::new(),
                query_sets: Vec::new(),
                base_fresh_claims: Vec::new(),
            },
            sources,
            steps: Vec::new(),
            response_range: 0..0,
            message_range: 0..0,
        })
    }

    pub(crate) fn ideal_image_request(
        &self,
        step: &CompactMaskingEntropyStep,
    ) -> Result<CompactMaskingIdealImageRequest, CompactMaskingEntropyError> {
        let step_index = usize::try_from(step.ordinal)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        let expected = self
            .steps
            .get(step_index)
            .ok_or(CompactMaskingEntropyError::DisclosureOutOfOrder)?;
        let active_range = match self.phase {
            CompactMaskingEntropyAuthorityPhase::AwaitingVerifierMessage => &self.response_range,
            CompactMaskingEntropyAuthorityPhase::AwaitingResponse => &self.message_range,
        };
        if expected != step || !active_range.contains(&step_index) {
            return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
        }
        if matches!(
            step.image,
            CompactMaskingDisclosureImage::FullCoordinateSpace
        ) && step.output_coordinate_count != step.conditional_rank
        {
            return Err(CompactMaskingEntropyError::RankFailure);
        }
        let transcript_prefix_binding = hash_transcript_prefix(
            self.coefficient_maps.certificate_digest(),
            self.identity,
            &self.transcript,
            self.next_move_ordinal,
        );
        Ok(CompactMaskingIdealImageRequest {
            attempt_identity: self.identity,
            step_ordinal: step.ordinal,
            verifier_move_ordinal: step.verifier_move_ordinal,
            output_coordinate_count: step.output_coordinate_count,
            independent_coordinate_count: step.conditional_rank,
            image: step.image,
            transcript_prefix_binding,
        })
    }

    /// Mints the coefficient owner's opaque conditional image from retained
    /// authenticated outputs and the actual decoded verifier-message prefix.
    /// The caller cannot provide query positions, challenges, output rows, or
    /// an image basis.
    pub(crate) fn prepare_coefficient_image(
        &self,
        step: &CompactMaskingEntropyStep,
        preceding_output_values: &[CompactChallengeField],
        retained_mirror_coefficients: Option<&[CompactChallengeField]>,
    ) -> Result<CompactConditionalImageRequest, CompactMaskingEntropyError> {
        let request = self.ideal_image_request(step)?;
        let CompactMaskingDisclosureImage::CoefficientMapImage {
            map_ordinal,
            first_output_coordinate,
        } = request.image
        else {
            return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
        };
        let query_positions;
        let runtime = match step.kind {
            CompactMaskingDisclosureKind::CrossEpochExplicitPoint => {
                CompactConditionalImageRuntime::CrossEpochExplicitPoint
            }
            CompactMaskingDisclosureKind::CfwOuterAuxiliary
            | CompactMaskingDisclosureKind::CfwOuterRound { .. } => {
                CompactConditionalImageRuntime::CfwOuter {
                    round_challenges: &self.transcript.cfw_round_challenges,
                }
            }
            CompactMaskingDisclosureKind::CfwOuterEvaluations => {
                return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
            }
            CompactMaskingDisclosureKind::CfwInnerTerminal => {
                CompactConditionalImageRuntime::CfwInnerTerminal {
                    round_challenges: &self.transcript.cfw_round_challenges,
                }
            }
            CompactMaskingDisclosureKind::WhirSumcheckAuxiliary {
                epoch,
                batch_ordinal,
            }
            | CompactMaskingDisclosureKind::WhirSumcheckRound {
                epoch,
                batch_ordinal,
                ..
            } => CompactConditionalImageRuntime::WhirSumcheck {
                round_challenges: sumcheck_challenges_for_prefix(
                    &self.transcript,
                    epoch,
                    batch_ordinal,
                )?,
            },
            CompactMaskingDisclosureKind::SourceQueries { .. }
            | CompactMaskingDisclosureKind::CarriedMaskQueries { .. } => {
                query_positions =
                    query_positions_for_disclosure(&self.inputs, &self.transcript, step.kind)?;
                CompactConditionalImageRuntime::ReedSolomonQueries {
                    preceding_query_positions: query_positions.preceding,
                    query_positions: query_positions.current,
                }
            }
            CompactMaskingDisclosureKind::FreshSourceQueries { .. }
            | CompactMaskingDisclosureKind::FreshMaskQueries { .. } => {
                query_positions =
                    query_positions_for_disclosure(&self.inputs, &self.transcript, step.kind)?;
                CompactConditionalImageRuntime::AffineMirrorQueries {
                    query_positions: query_positions.current,
                    retained_mirror_coefficients: retained_mirror_coefficients
                        .ok_or(CompactMaskingEntropyError::MissingTranscriptInput)?,
                }
            }
            _ => return Err(CompactMaskingEntropyError::InvalidCoefficientMap),
        };
        self.coefficient_maps
            .prepare_conditional_image(
                map_ordinal,
                step.ordinal,
                first_output_coordinate,
                step.output_coordinate_count,
                request.independent_coordinate_count,
                request.transcript_prefix_binding,
                preceding_output_values,
                runtime,
            )
            .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientMap)
    }

    /// Derives the final outer-evaluation image after the terminal matrix
    /// values have been sampled. Both components belong to one atomic prover
    /// response, so simulator order is terminal values first and outer
    /// evaluations second even though canonical wire order is the reverse.
    pub(crate) fn prepare_cfw_final_outer_image(
        &self,
        step: &CompactMaskingEntropyStep,
        preceding_output_values: &[CompactChallengeField],
        terminal_values: &[CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
    ) -> Result<CompactConditionalImageRequest, CompactMaskingEntropyError> {
        let request = self.ideal_image_request(step)?;
        let CompactMaskingDisclosureImage::CoefficientMapImage {
            map_ordinal,
            first_output_coordinate,
        } = request.image
        else {
            return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
        };
        if step.kind != CompactMaskingDisclosureKind::CfwOuterEvaluations {
            return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
        }
        let constraint_combining_challenge = self
            .transcript
            .cfw_constraint_combining_challenge
            .ok_or(CompactMaskingEntropyError::MissingTranscriptInput)?;
        let round_count = self
            .inputs
            .cfw_configuration
            .geometry()
            .sumcheck_round_count();
        if self.transcript.cfw_equality_point.len() != round_count
            || self.transcript.cfw_round_challenges.len() != round_count
        {
            return Err(CompactMaskingEntropyError::MissingTranscriptInput);
        }
        self.coefficient_maps
            .prepare_conditional_image(
                map_ordinal,
                step.ordinal,
                first_output_coordinate,
                step.output_coordinate_count,
                request.independent_coordinate_count,
                request.transcript_prefix_binding,
                preceding_output_values,
                CompactConditionalImageRuntime::CfwFinalOuterEvaluations {
                    constraint_combining_challenge,
                    equality_point: &self.transcript.cfw_equality_point,
                    round_challenges: &self.transcript.cfw_round_challenges,
                    terminal_values,
                },
            )
            .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientMap)
    }

    #[cfg(test)]
    pub(crate) fn execute_coefficient_image(
        &self,
        step: &CompactMaskingEntropyStep,
        request: &CompactConditionalImageRequest,
        independent_coordinates: &[CompactChallengeField],
    ) -> Result<Vec<CompactChallengeField>, CompactMaskingEntropyError> {
        let image_request = self.ideal_image_request(step)?;
        self.coefficient_maps
            .execute_conditional_image(
                request,
                step.ordinal,
                image_request.transcript_prefix_binding,
                independent_coordinates,
            )
            .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientMap)
    }

    /// Checks a real emitted disclosure against the independently derived
    /// conditional image for the current authenticated transcript prefix.
    pub(crate) fn verify_coefficient_image_output(
        &self,
        step: &CompactMaskingEntropyStep,
        preceding_output_values: &[CompactChallengeField],
        retained_mirror_coefficients: Option<&[CompactChallengeField]>,
        candidate_output: &[CompactChallengeField],
    ) -> Result<(), CompactMaskingEntropyError> {
        let image_request = self.ideal_image_request(step)?;
        let coefficient_request = self.prepare_coefficient_image(
            step,
            preceding_output_values,
            retained_mirror_coefficients,
        )?;
        self.coefficient_maps
            .verify_conditional_image_output(
                &coefficient_request,
                step.ordinal,
                image_request.transcript_prefix_binding,
                candidate_output,
            )
            .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientMap)
    }

    pub(crate) fn verify_cfw_final_outer_output(
        &self,
        step: &CompactMaskingEntropyStep,
        preceding_output_values: &[CompactChallengeField],
        terminal_values: &[CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
        candidate_output: &[CompactChallengeField],
    ) -> Result<(), CompactMaskingEntropyError> {
        let image_request = self.ideal_image_request(step)?;
        let coefficient_request =
            self.prepare_cfw_final_outer_image(step, preceding_output_values, terminal_values)?;
        self.coefficient_maps
            .verify_conditional_image_output(
                &coefficient_request,
                step.ordinal,
                image_request.transcript_prefix_binding,
                candidate_output,
            )
            .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientMap)
    }

    /// Returns the exact output-coordinate covector for a fresh-message
    /// identity reveal. Encoding-randomness coordinates have coefficient zero.
    #[cfg(test)]
    pub(crate) fn reveal_output_covector(
        &self,
        step: &CompactMaskingEntropyStep,
    ) -> Result<Vec<CompactChallengeField>, CompactMaskingEntropyError> {
        self.ideal_image_request(step)?;
        linear_claim_output_covector(&self.inputs, &self.transcript, step)
    }

    pub(crate) fn next_base_claim_requirement(
        &self,
    ) -> Result<Option<CompactBaseFreshClaimRequirement>, CompactMaskingEntropyError> {
        if self.phase != CompactMaskingEntropyAuthorityPhase::AwaitingResponse {
            return Err(CompactMaskingEntropyError::WrongAuthorityPhase);
        }
        let (_, roles) = self.current_response()?;
        let Some(role) = roles.iter().find(|role| role.role_tag == 18) else {
            return Ok(None);
        };
        let epoch = self
            .inputs
            .whir_epochs
            .iter()
            .find(|epoch| epoch.epoch == role.epoch)
            .ok_or(CompactMaskingEntropyError::InvalidContract)?;
        Ok(Some(CompactBaseFreshClaimRequirement {
            epoch: role.epoch,
            coefficient_count: base_fresh_message_dimension(epoch)?,
        }))
    }

    pub(crate) fn authorize_next_response(
        &mut self,
        base_claim: Option<&CompactBaseFreshClaimCoefficients>,
    ) -> Result<&[CompactMaskingEntropyStep], CompactMaskingEntropyError> {
        if self.phase != CompactMaskingEntropyAuthorityPhase::AwaitingResponse {
            return Err(CompactMaskingEntropyError::WrongAuthorityPhase);
        }
        let requirement = self.next_base_claim_requirement()?;
        match (requirement, base_claim) {
            (None, None) => {}
            (Some(requirement), Some(claim))
                if claim.epoch == requirement.epoch
                    && u64::try_from(claim.coefficients.len()).ok()
                        == Some(requirement.coefficient_count)
                    && !claim
                        .coefficients
                        .iter()
                        .all(|coefficient| *coefficient == CompactChallengeField::ZERO) =>
            {
                if self
                    .transcript
                    .base_fresh_claims
                    .iter()
                    .any(|record| record.epoch == claim.epoch)
                {
                    return Err(CompactMaskingEntropyError::DuplicateTranscriptInput);
                }
                self.transcript.base_fresh_claims.push(claim.clone());
            }
            _ => return Err(CompactMaskingEntropyError::InvalidCoefficientVector),
        }

        let full = derive_available_scalar_steps(
            &self.inputs,
            self.coefficient_maps,
            &self.transcript,
            self.next_move_ordinal,
        )?;
        let start = self.steps.len();
        append_streaming_steps(&mut self.sources, &mut self.steps, full)?;
        self.response_range = start..self.steps.len();
        self.phase = CompactMaskingEntropyAuthorityPhase::AwaitingVerifierMessage;
        Ok(&self.steps[self.response_range.clone()])
    }

    pub(crate) fn ingest_verifier_message(
        &mut self,
        move_ordinal: u32,
        message: &DecodedFixedUniformVerifierMessage,
    ) -> Result<&[CompactMaskingEntropyStep], CompactMaskingEntropyError> {
        if self.phase != CompactMaskingEntropyAuthorityPhase::AwaitingVerifierMessage
            || usize::try_from(move_ordinal).ok() != Some(self.next_move_ordinal)
        {
            return Err(CompactMaskingEntropyError::WrongAuthorityPhase);
        }
        let move_contract = self.current_move()?.clone();
        validate_decoded_message(&move_contract, message)?;
        append_message_to_transcript(&mut self.transcript, &move_contract, message)?;
        let mut pending = Vec::new();
        append_query_steps_for_move(
            &self.inputs,
            self.coefficient_maps,
            &self.transcript,
            move_ordinal,
            &mut pending,
        )?;
        pending.sort_by_key(|step| step.intra_move_ordinal);
        let start = self.steps.len();
        append_streaming_steps(&mut self.sources, &mut self.steps, pending)?;
        self.message_range = start..self.steps.len();
        self.next_move_ordinal += 1;
        self.phase = CompactMaskingEntropyAuthorityPhase::AwaitingResponse;
        Ok(&self.steps[self.message_range.clone()])
    }

    #[cfg(test)]
    pub(crate) fn finish(
        self,
    ) -> Result<CompactMaskingEntropyCertificate, CompactMaskingEntropyError> {
        if self.phase != CompactMaskingEntropyAuthorityPhase::AwaitingResponse
            || self.next_move_ordinal != self.inputs.verifier_moves.len()
        {
            return Err(CompactMaskingEntropyError::WrongAuthorityPhase);
        }
        let (certificate, certified_sources) = certify_compact_masking_entropy_with_sources(
            &self.inputs,
            self.coefficient_maps,
            &self.transcript,
        )?;
        if self.steps != certificate.steps || self.sources != certified_sources {
            return Err(CompactMaskingEntropyError::CertificateMismatch);
        }
        Ok(certificate)
    }

    fn current_move(&self) -> Result<&CompactVerifierMoveContract, CompactMaskingEntropyError> {
        self.inputs
            .verifier_moves
            .get(self.next_move_ordinal)
            .ok_or(CompactMaskingEntropyError::WrongAuthorityPhase)
    }

    fn current_response(
        &self,
    ) -> Result<
        (
            &CompactResponseMerkleGeometry,
            &[CompactResponseComponentRoleContract],
        ),
        CompactMaskingEntropyError,
    > {
        let geometry = self
            .inputs
            .response_merkle_geometries
            .get(self.next_move_ordinal)
            .ok_or(CompactMaskingEntropyError::WrongAuthorityPhase)?;
        let roles = self
            .inputs
            .response_component_roles
            .get(self.next_move_ordinal)
            .ok_or(CompactMaskingEntropyError::WrongAuthorityPhase)?;
        Ok((geometry, roles))
    }
}

/// Verifies the first live constrained disclosures against the independently
/// compiled coefficient maps, canonical proof prefix, and authenticated
/// transcript cursor that precede them. This is a production generation gate,
/// not the ideal simulator: it accepts only values generated by the real prover
/// state.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_selected_compact_cross_epoch_masking_prefix(
    inputs: CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    proof_attempt_identifier: [u8; 32],
    canonical_public_input_bytes: &[u8],
    canonical_exposed_proof_prefix: &[u8],
    canonical_transcript_cursor_bytes: &[u8],
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    cross_epoch_disclosures: [CompactChallengeField; 3],
    cfw_auxiliary_disclosure: CompactChallengeField,
) -> Result<CompactMaskingAttemptIdentity, CompactMaskingEntropyError> {
    if canonical_public_input_bytes.is_empty()
        || canonical_exposed_proof_prefix.is_empty()
        || canonical_transcript_cursor_bytes.is_empty()
        || completed_messages.len() != 2
    {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    let live_prefix_binding = hash_framed_parts_512(
        LIVE_PREFIX_BINDING_DOMAIN,
        &[
            &coefficient_maps.certificate_digest(),
            canonical_public_input_bytes,
            canonical_exposed_proof_prefix,
            canonical_transcript_cursor_bytes,
        ],
    );
    let identity =
        CompactMaskingAttemptIdentity::new(proof_attempt_identifier, 0, live_prefix_binding);
    let mut authority = CompactMaskingEntropyAuthority::begin(inputs, coefficient_maps, identity)?;

    for (move_ordinal, message) in completed_messages.iter().enumerate() {
        if !authority.authorize_next_response(None)?.is_empty() {
            return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
        }
        let move_ordinal = u32::try_from(move_ordinal)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        if !authority
            .ingest_verifier_message(move_ordinal, message)?
            .is_empty()
        {
            return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
        }
    }

    let steps = authority.authorize_next_response(None)?.to_vec();
    let [cross_epoch_step, cfw_auxiliary_step] = steps.as_slice() else {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    };
    if cross_epoch_step.kind() != CompactMaskingDisclosureKind::CrossEpochExplicitPoint
        || cross_epoch_step.output_coordinate_count() != 3
        || cross_epoch_step.conditional_rank() != 2
        || cfw_auxiliary_step.kind() != CompactMaskingDisclosureKind::CfwOuterAuxiliary
        || cfw_auxiliary_step.output_coordinate_count() != 1
        || cfw_auxiliary_step.conditional_rank() != 1
    {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    }
    authority.verify_coefficient_image_output(
        cross_epoch_step,
        &[],
        None,
        &cross_epoch_disclosures,
    )?;
    authority.verify_coefficient_image_output(
        cfw_auxiliary_step,
        &[],
        None,
        &[cfw_auxiliary_disclosure],
    )?;
    Ok(identity)
}

/// Verifies one live CFW round polynomial against the exact affine image left
/// by the auxiliary target and all preceding round polynomials.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_selected_compact_cfw_round_masking(
    inputs: CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    preceding_outer_outputs: &[CompactChallengeField],
    round_ordinal: u32,
    round_polynomial: &[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH],
) -> Result<(), CompactMaskingEntropyError> {
    let round_index = usize::try_from(round_ordinal)
        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    let expected_message_count = round_index
        .checked_add(3)
        .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
    let expected_preceding_output_count = round_index
        .checked_mul(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
        .and_then(|count| count.checked_add(1))
        .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
    if completed_messages.len() != expected_message_count
        || preceding_outer_outputs.len() != expected_preceding_output_count
    {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    let compiler_round_rank = certified_cfw_round_conditional_rank(
        coefficient_maps,
        u64::try_from(inputs.cfw_configuration.geometry().sumcheck_round_count())
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
    )?;
    let mut authority = replay_selected_compact_cfw_masking_prefix(
        inputs,
        coefficient_maps,
        identity,
        completed_messages,
    )?;
    let steps = authority.authorize_next_response(None)?.to_vec();
    let [round_step] = steps.as_slice() else {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    };
    if round_step.kind() != (CompactMaskingDisclosureKind::CfwOuterRound { round_ordinal })
        || round_step.output_coordinate_count()
            != u64::try_from(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?
    {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    }
    if compiler_round_rank != CFW_OUTER_MASK_MESSAGE_LENGTH_U64 - 1
        || round_step.conditional_rank() != compiler_round_rank
    {
        return Err(CompactMaskingEntropyError::RankFailure);
    }
    authority.verify_coefficient_image_output(
        round_step,
        preceding_outer_outputs,
        None,
        round_polynomial,
    )
}

/// Verifies the final live CFW masking response after every round challenge is
/// fixed. The terminal matrix values are a full-rank translation of the
/// compiled inner-mask image. Conditioned on those values, the verifier's
/// final CFW equation translates the rank-`round_count - 1` outer-mask image.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_selected_compact_cfw_finish_masking(
    inputs: CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    preceding_outer_outputs: &[CompactChallengeField],
    outer_evaluations: &[CompactChallengeField],
    final_values: &[CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
) -> Result<(), CompactMaskingEntropyError> {
    let cfw_round_count = inputs.cfw_configuration.geometry().sumcheck_round_count();
    let expected_message_count = cfw_round_count
        .checked_add(3)
        .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
    let expected_preceding_output_count = cfw_round_count
        .checked_mul(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
        .and_then(|count| count.checked_add(1))
        .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
    if completed_messages.len() != expected_message_count
        || preceding_outer_outputs.len() != expected_preceding_output_count
        || outer_evaluations.len() != cfw_round_count
    {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    let mut authority = replay_selected_compact_cfw_masking_prefix(
        inputs,
        coefficient_maps,
        identity,
        completed_messages,
    )?;
    let steps = authority.authorize_next_response(None)?.to_vec();
    let [terminal_step, outer_step] = steps.as_slice() else {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    };
    if outer_step.kind() != CompactMaskingDisclosureKind::CfwOuterEvaluations
        || outer_step.output_coordinate_count()
            != u64::try_from(cfw_round_count)
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?
        || terminal_step.kind() != CompactMaskingDisclosureKind::CfwInnerTerminal
        || terminal_step.output_coordinate_count() != COMPACT_CFW_MATRIX_COUNT as u64
    {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    }
    authority.verify_coefficient_image_output(terminal_step, &[], None, final_values)?;
    authority.verify_cfw_final_outer_output(
        outer_step,
        preceding_outer_outputs,
        final_values,
        outer_evaluations,
    )
}

/// Verifies the live auxiliary target of one compact WHIR masked-sumcheck
/// batch against the independently compiled coefficient image at the exact
/// authenticated transcript prefix that precedes the response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactWhirSumcheckBatchCoordinate {
    epoch: u8,
    batch_ordinal: u8,
}

impl CompactWhirSumcheckBatchCoordinate {
    pub(crate) const fn new(epoch: u8, batch_ordinal: u8) -> Self {
        Self {
            epoch,
            batch_ordinal,
        }
    }
}

pub(crate) fn verify_selected_compact_whir_sumcheck_auxiliary_masking(
    inputs: CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    verified_base_prefix: Option<&CompactVerifiedBaseMaskingPrefix>,
    coordinate: CompactWhirSumcheckBatchCoordinate,
    auxiliary_target: CompactChallengeField,
) -> Result<(), CompactMaskingEntropyError> {
    let CompactWhirSumcheckBatchCoordinate {
        epoch,
        batch_ordinal,
    } = coordinate;
    let mut authority = replay_selected_compact_masking_prefix(
        inputs,
        coefficient_maps,
        identity,
        completed_messages,
        verified_base_prefix,
    )?;
    let steps = authority.authorize_next_response(None)?.to_vec();
    let [auxiliary_step] = steps.as_slice() else {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    };
    if auxiliary_step.kind()
        != (CompactMaskingDisclosureKind::WhirSumcheckAuxiliary {
            epoch,
            batch_ordinal,
        })
        || auxiliary_step.output_coordinate_count() != 1
        || auxiliary_step.conditional_rank() != 1
    {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    }
    authority.verify_coefficient_image_output(auxiliary_step, &[], None, &[auxiliary_target])
}

/// Verifies one live compact WHIR masked-sumcheck wire after all preceding
/// outputs from that mask group and the verifier challenges that condition it
/// have entered the authenticated transcript.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_selected_compact_whir_sumcheck_round_masking(
    inputs: CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    verified_base_prefix: Option<&CompactVerifiedBaseMaskingPrefix>,
    epoch: u8,
    batch_ordinal: u8,
    round_ordinal: u32,
    preceding_sumcheck_outputs: &[CompactChallengeField],
    round_wire: &[CompactChallengeField],
) -> Result<(), CompactMaskingEntropyError> {
    let expected_preceding_output_count = usize::try_from(round_ordinal)
        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
    if preceding_sumcheck_outputs.len() != expected_preceding_output_count || round_wire.len() != 2
    {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    let mut authority = replay_selected_compact_masking_prefix(
        inputs,
        coefficient_maps,
        identity,
        completed_messages,
        verified_base_prefix,
    )?;
    let steps = authority.authorize_next_response(None)?.to_vec();
    let [round_step] = steps.as_slice() else {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    };
    if round_step.kind()
        != (CompactMaskingDisclosureKind::WhirSumcheckRound {
            epoch,
            batch_ordinal,
            round_ordinal,
        })
        || round_step.output_coordinate_count() != 2
        || round_step.conditional_rank() != 2
    {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    }
    authority.verify_coefficient_image_output(
        round_step,
        preceding_sumcheck_outputs,
        None,
        round_wire,
    )
}

/// Verifies the live encoded-source openings selected by one compact WHIR
/// code-switch message. The verifier prefix determines the distinct query
/// positions; callers provide only the emitted query-major leaf values.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_selected_compact_whir_source_query_masking(
    inputs: CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    verified_base_prefix: Option<&CompactVerifiedBaseMaskingPrefix>,
    epoch: u8,
    source_ordinal: u8,
    query_outputs: &[CompactChallengeField],
) -> Result<(), CompactMaskingEntropyError> {
    if completed_messages.is_empty() || completed_messages.len() >= inputs.verifier_moves.len() {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    let selected_message_index = completed_messages.len() - 1;
    let mut authority = replay_selected_compact_masking_prefix(
        inputs,
        coefficient_maps,
        identity,
        &completed_messages[..selected_message_index],
        verified_base_prefix,
    )?;
    authority.authorize_next_response(None)?;
    let selected_steps = authority
        .ingest_verifier_message(
            u32::try_from(selected_message_index)
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
            &completed_messages[selected_message_index],
        )?
        .to_vec();

    let [source_query_step] = selected_steps.as_slice() else {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    };
    if source_query_step.kind()
        != (CompactMaskingDisclosureKind::SourceQueries {
            epoch,
            source_ordinal,
        })
        || usize::try_from(source_query_step.output_coordinate_count()).ok()
            != Some(query_outputs.len())
        || source_query_step.conditional_rank() != source_query_step.output_coordinate_count()
    {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    }
    authority.verify_coefficient_image_output(source_query_step, &[], None, query_outputs)
}

/// Replays the selected first-epoch relation covectors from canonical public
/// input and the exact authenticated verifier prefix, then authorizes its fresh
/// base-case claim against the production conditional-entropy owner. The main
/// epoch uses the bounded begin/finish API below.
pub(crate) fn derive_selected_compact_pre_challenge_base_covector(
    inputs: CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    public_covector_authority: &CompactFactorOnePublicCovectorAuthority<'_>,
    canonical_exposed_proof_prefix: &[u8],
    completed_messages: &[DecodedFixedUniformVerifierMessage],
) -> Result<CompactVerifiedWhirBaseCovector, CompactMaskingEntropyError> {
    let [pre_challenge_epoch, _main_epoch] = inputs.whir_epochs else {
        return Err(CompactMaskingEntropyError::InvalidContract);
    };
    let epoch = pre_challenge_epoch.epoch;
    let mut derivation = begin_selected_compact_whir_base_covector_derivation(
        &inputs,
        identity,
        public_covector_authority,
        canonical_exposed_proof_prefix,
        completed_messages,
        epoch,
    )?;
    let authorization = match derivation
        .advance(1)
        .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientVector)?
    {
        CompactFactorOnePublicCovectorPoll::Complete(authorization) => authorization,
        CompactFactorOnePublicCovectorPoll::WorkCompleted { .. } => {
            return Err(CompactMaskingEntropyError::InvalidCoefficientVector);
        }
    };
    finish_selected_compact_whir_base_covector_derivation(
        inputs,
        coefficient_maps,
        identity,
        public_covector_authority,
        canonical_exposed_proof_prefix,
        completed_messages,
        None,
        epoch,
        authorization,
    )
}

pub(crate) fn begin_selected_compact_whir_base_covector_derivation(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    identity: CompactMaskingAttemptIdentity,
    public_covector_authority: &CompactFactorOnePublicCovectorAuthority<'_>,
    canonical_exposed_proof_prefix: &[u8],
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    epoch: u8,
) -> Result<CompactFactorOnePublicCovectorDerivation, CompactMaskingEntropyError> {
    let prefix = selected_compact_whir_base_semantic_prefix(
        inputs,
        identity,
        public_covector_authority,
        canonical_exposed_proof_prefix,
        completed_messages,
        epoch,
    )?;
    public_covector_authority
        .begin_prefix_derivation(prefix)
        .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientVector)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_selected_compact_whir_base_covector_derivation(
    inputs: CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    public_covector_authority: &CompactFactorOnePublicCovectorAuthority<'_>,
    canonical_exposed_proof_prefix: &[u8],
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    verified_previous_base_prefix: Option<&CompactVerifiedBaseMaskingPrefix>,
    epoch: u8,
    mut authorization: Box<CompactFactorOneCarriedCovector>,
) -> Result<CompactVerifiedWhirBaseCovector, CompactMaskingEntropyError> {
    let prefix = selected_compact_whir_base_semantic_prefix(
        &inputs,
        identity,
        public_covector_authority,
        canonical_exposed_proof_prefix,
        completed_messages,
        epoch,
    )?;
    if authorization.epoch() != Some(epoch)
        || !authorization.authorizes(&prefix, public_covector_authority.public_input_binding())
    {
        return Err(CompactMaskingEntropyError::InvalidCoefficientVector);
    }
    let coefficients = authorization
        .coefficients()
        .ok_or(CompactMaskingEntropyError::InvalidCoefficientVector)?
        .to_vec();
    authorization
        .consume(&prefix, public_covector_authority.public_input_binding())
        .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientVector)?;
    let claim = CompactBaseFreshClaimCoefficients {
        epoch,
        coefficients: coefficients.clone(),
    };
    let epoch_contract = inputs
        .whir_epochs
        .iter()
        .find(|epoch_contract| epoch_contract.epoch == epoch)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    let mask_contracts = epoch_contract
        .external_mask_groups
        .iter()
        .chain(&epoch_contract.internal_mask_groups)
        .copied()
        .collect::<Vec<_>>();
    let final_fold = inputs
        .whir_folds
        .iter()
        .find(|fold| fold.epoch == epoch && fold.batch_ordinal == 3)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    let source_length = usize::try_from(final_fold.message_length)
        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    let mut masking_authority = replay_selected_compact_masking_prefix(
        inputs,
        coefficient_maps,
        identity,
        completed_messages,
        verified_previous_base_prefix,
    )?;
    let steps = masking_authority
        .authorize_next_response(Some(&claim))?
        .to_vec();
    let [claim_step] = steps.as_slice() else {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    };
    if claim_step.kind() != (CompactMaskingDisclosureKind::BaseFreshClaim { epoch })
        || claim_step.output_coordinate_count() != 1
        || claim_step.conditional_rank() != 1
        || claim_step.image != CompactMaskingDisclosureImage::FullCoordinateSpace
    {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    }

    let source = coefficients
        .get(..source_length)
        .ok_or(CompactMaskingEntropyError::InvalidCoefficientVector)?
        .to_vec();
    let mut coefficient_offset = source_length;
    let mut mask_groups = Vec::new();
    for group in mask_contracts {
        let width = usize::try_from(group.width)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        let message_length = usize::try_from(group.message_length)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        let mut group_covectors = Vec::new();
        group_covectors
            .try_reserve_exact(width)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        for _lane_ordinal in 0..width {
            let end = coefficient_offset
                .checked_add(message_length)
                .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
            group_covectors.push(
                coefficients
                    .get(coefficient_offset..end)
                    .ok_or(CompactMaskingEntropyError::InvalidCoefficientVector)?
                    .to_vec(),
            );
            coefficient_offset = end;
        }
        mask_groups.push(group_covectors);
    }
    if coefficient_offset != coefficients.len() {
        return Err(CompactMaskingEntropyError::InvalidCoefficientVector);
    }
    Ok(CompactVerifiedWhirBaseCovector {
        source,
        mask_groups,
    })
}

fn selected_compact_whir_base_semantic_prefix(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    identity: CompactMaskingAttemptIdentity,
    public_covector_authority: &CompactFactorOnePublicCovectorAuthority<'_>,
    canonical_exposed_proof_prefix: &[u8],
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    epoch: u8,
) -> Result<CompactMaskingSemanticPrefix, CompactMaskingEntropyError> {
    if canonical_exposed_proof_prefix.is_empty()
        || completed_messages.is_empty()
        || completed_messages.len() >= inputs.verifier_moves.len()
    {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    let next_move = inputs
        .verifier_moves
        .get(completed_messages.len())
        .ok_or(CompactMaskingEntropyError::MissingTranscriptInput)?;
    let [role] = next_move.role_coordinates.as_slice() else {
        return Err(CompactMaskingEntropyError::InvalidContract);
    };
    if role.role_tag != 10
        || role.epoch != epoch
        || role.batch_ordinal != 0
        || role.round_ordinal != 0
        || usize::try_from(next_move.ordinal).ok() != Some(completed_messages.len())
        || public_covector_authority.contract_source_hash()
            != inputs
                .canonical_source_hash()
                .map_err(|_| CompactMaskingEntropyError::InvalidContract)?
                .into_bytes()
    {
        return Err(CompactMaskingEntropyError::InvalidContract);
    }
    let prefix = CompactMaskingSemanticPrefix::from_validated_transcript(
        identity,
        next_move.ordinal,
        role.epoch,
        public_covector_authority.contract_source_hash(),
        canonical_exposed_proof_prefix.to_vec().into_boxed_slice(),
        completed_messages.to_vec().into_boxed_slice(),
    )
    .map_err(|_| CompactMaskingEntropyError::MissingTranscriptInput)?;
    Ok(prefix)
}

/// Checks the live Construction 7.2 reveal response at the exact role-10
/// transcript prefix. The entropy authority owns the one lost claim
/// coordinate; the prover state separately checks that the emitted affine
/// reveal satisfies that same claim equation.
pub(crate) fn verify_selected_compact_whir_base_reveal_masking(
    inputs: CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    verified_previous_base_prefix: Option<&CompactVerifiedBaseMaskingPrefix>,
    epoch: u8,
    claim_coefficients: &[CompactChallengeField],
) -> Result<CompactVerifiedBaseRevealMasking, CompactMaskingEntropyError> {
    let (mut authority, _last_response_steps, last_message_steps) =
        replay_selected_compact_masking_prefix_with_base_claim(
            inputs,
            coefficient_maps,
            identity,
            completed_messages,
            verified_previous_base_prefix,
            epoch,
            claim_coefficients,
        )?;
    if !last_message_steps.is_empty() {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    }
    let reveal_steps = authority.authorize_next_response(None)?.to_vec();
    validate_base_reveal_steps(
        &authority.inputs,
        epoch,
        &reveal_steps,
        expected_base_reveal_coordinate_count(&authority.inputs, epoch)?,
    )?;
    Ok(CompactVerifiedBaseRevealMasking {
        identity,
        claim: CompactBaseFreshClaimCoefficients {
            epoch,
            coefficients: claim_coefficients.to_vec(),
        },
        completed_messages: completed_messages.to_vec().into_boxed_slice(),
    })
}

/// Checks every selected final query opened after the blinded response. The
/// response-tree owner supplies canonical leaf values; this owner rederives
/// their response components and query positions from the decoded contract
/// and authenticated verifier messages before checking each conditional image.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_selected_compact_whir_base_final_query_masking(
    inputs: CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    verified_previous_base_prefix: Option<&CompactVerifiedBaseMaskingPrefix>,
    epoch: u8,
    verified_reveal: &CompactVerifiedBaseRevealMasking,
    fresh_source_mirror_coefficients: &[CompactChallengeField],
    fresh_mask_mirror_coefficients: &[Vec<CompactChallengeField>],
    query_leaves: &[CompactMaskingQueryLeaf],
) -> Result<CompactVerifiedBaseMaskingPrefix, CompactMaskingEntropyError> {
    if query_leaves.is_empty() {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    if !verified_reveal.authorizes_final_query(identity, epoch, completed_messages) {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    let (authority, reveal_steps, final_query_steps) =
        replay_selected_compact_masking_prefix_with_base_claim(
            inputs,
            coefficient_maps,
            identity,
            completed_messages,
            verified_previous_base_prefix,
            epoch,
            &verified_reveal.claim.coefficients,
        )?;
    validate_base_reveal_steps(
        &authority.inputs,
        epoch,
        &reveal_steps,
        expected_base_reveal_coordinate_count(&authority.inputs, epoch)?,
    )?;

    let epoch_contract = authority
        .inputs
        .whir_epochs
        .iter()
        .find(|contract| contract.epoch == epoch)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    if fresh_mask_mirror_coefficients.len()
        != epoch_contract
            .external_mask_groups
            .len()
            .checked_add(epoch_contract.internal_mask_groups.len())
            .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?
    {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    let mut sorted_query_leaves = Vec::new();
    sorted_query_leaves
        .try_reserve_exact(query_leaves.len())
        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    sorted_query_leaves.extend(query_leaves);
    sorted_query_leaves
        .sort_unstable_by_key(|query_leaf| (query_leaf.response_ordinal, query_leaf.leaf_ordinal));
    if sorted_query_leaves.windows(2).any(|adjacent| {
        adjacent[0].response_ordinal == adjacent[1].response_ordinal
            && adjacent[0].leaf_ordinal == adjacent[1].leaf_ordinal
    }) {
        return Err(CompactMaskingEntropyError::DuplicateTranscriptInput);
    }
    let mut consumed_query_leaves = vec![false; sorted_query_leaves.len()];
    for step in &final_query_steps {
        let positions =
            query_positions_for_disclosure(&authority.inputs, &authority.transcript, step.kind())?;
        let (preceding_output, candidate_output) = if positions.preceding.is_empty() {
            (
                Vec::new(),
                query_leaf_values_for_step(
                    &authority.inputs,
                    step.kind(),
                    positions.current,
                    &sorted_query_leaves,
                    &mut consumed_query_leaves,
                )?,
            )
        } else {
            if !matches!(
                step.kind(),
                CompactMaskingDisclosureKind::CarriedMaskQueries {
                    epoch: 2,
                    contract_role_tag: 1,
                    ..
                }
            ) {
                return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
            }
            let mut temporary_consumption = vec![false; sorted_query_leaves.len()];
            let preceding_output = query_leaf_values_for_step(
                &authority.inputs,
                step.kind(),
                positions.preceding,
                &sorted_query_leaves,
                &mut temporary_consumption,
            )?;
            temporary_consumption.fill(false);
            let candidate_output = query_leaf_values_for_step(
                &authority.inputs,
                step.kind(),
                positions.current,
                &sorted_query_leaves,
                &mut temporary_consumption,
            )?;
            let mut union_positions = Vec::new();
            union_positions
                .try_reserve_exact(
                    positions
                        .preceding
                        .len()
                        .checked_add(positions.current.len())
                        .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?,
                )
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
            union_positions.extend_from_slice(positions.preceding);
            union_positions.extend_from_slice(positions.current);
            union_positions.sort_unstable();
            union_positions.dedup();
            query_leaf_values_for_step(
                &authority.inputs,
                step.kind(),
                &union_positions,
                &sorted_query_leaves,
                &mut consumed_query_leaves,
            )?;
            (preceding_output, candidate_output)
        };
        match step.kind() {
            CompactMaskingDisclosureKind::SourceQueries {
                epoch: step_epoch,
                source_ordinal: 3,
            }
            | CompactMaskingDisclosureKind::CarriedMaskQueries {
                epoch: step_epoch, ..
            } if step_epoch == epoch => {
                authority.verify_coefficient_image_output(
                    step,
                    &preceding_output,
                    None,
                    &candidate_output,
                )?;
            }
            CompactMaskingDisclosureKind::FreshSourceQueries { epoch: step_epoch }
                if step_epoch == epoch =>
            {
                authority.verify_coefficient_image_output(
                    step,
                    &[],
                    Some(fresh_source_mirror_coefficients),
                    &candidate_output,
                )?;
            }
            CompactMaskingDisclosureKind::FreshMaskQueries {
                epoch: step_epoch,
                group_ordinal,
            } if step_epoch == epoch => {
                authority.verify_coefficient_image_output(
                    step,
                    &[],
                    Some(
                        fresh_mask_mirror_coefficients
                            .get(usize::from(group_ordinal))
                            .ok_or(CompactMaskingEntropyError::MissingTranscriptInput)?,
                    ),
                    &candidate_output,
                )?;
            }
            _ => return Err(CompactMaskingEntropyError::DisclosureOutOfOrder),
        }
    }
    if final_query_steps.is_empty() || consumed_query_leaves.iter().any(|consumed| !consumed) {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    }
    Ok(CompactVerifiedBaseMaskingPrefix {
        identity,
        claim: verified_reveal.claim.clone(),
        completed_messages: completed_messages.to_vec().into_boxed_slice(),
    })
}

fn replay_selected_compact_masking_prefix_with_base_claim<'contract>(
    inputs: CompactPublicKeyVerifierInputs<'contract>,
    coefficient_maps: &'contract CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    verified_previous_base_prefix: Option<&CompactVerifiedBaseMaskingPrefix>,
    epoch: u8,
    claim_coefficients: &[CompactChallengeField],
) -> Result<
    (
        CompactMaskingEntropyAuthority<'contract>,
        Vec<CompactMaskingEntropyStep>,
        Vec<CompactMaskingEntropyStep>,
    ),
    CompactMaskingEntropyError,
> {
    if completed_messages.is_empty() || completed_messages.len() > inputs.verifier_moves.len() {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    if verified_previous_base_prefix
        .is_some_and(|prefix| !prefix.authorizes_replay(identity, completed_messages))
    {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    let claim = CompactBaseFreshClaimCoefficients {
        epoch,
        coefficients: claim_coefficients.to_vec(),
    };
    let mut authority = CompactMaskingEntropyAuthority::begin(inputs, coefficient_maps, identity)?;
    let mut last_response_steps = Vec::new();
    let mut last_message_steps = Vec::new();
    for (move_index, message) in completed_messages.iter().enumerate() {
        let response_steps = if let Some(requirement) = authority.next_base_claim_requirement()? {
            let required_claim = if requirement.epoch == claim.epoch {
                &claim
            } else {
                verified_previous_base_prefix
                    .map(|prefix| &prefix.claim)
                    .filter(|previous_claim| previous_claim.epoch == requirement.epoch)
                    .ok_or(CompactMaskingEntropyError::InvalidCoefficientVector)?
            };
            authority.authorize_next_response(Some(required_claim))?
        } else {
            authority.authorize_next_response(None)?
        };
        if move_index + 1 == completed_messages.len() {
            last_response_steps = response_steps.to_vec();
        }
        let move_ordinal = u32::try_from(move_index)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        let message_steps = authority.ingest_verifier_message(move_ordinal, message)?;
        if move_index + 1 == completed_messages.len() {
            last_message_steps = message_steps.to_vec();
        }
    }
    Ok((authority, last_response_steps, last_message_steps))
}

fn validate_base_reveal_steps(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    epoch: u8,
    steps: &[CompactMaskingEntropyStep],
    expected_reveal_coordinate_count: usize,
) -> Result<(), CompactMaskingEntropyError> {
    let epoch_contract = inputs
        .whir_epochs
        .iter()
        .find(|contract| contract.epoch == epoch)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    let expected_step_count = epoch_contract
        .external_mask_groups
        .len()
        .checked_add(epoch_contract.internal_mask_groups.len())
        .and_then(|count| count.checked_add(2))
        .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
    if steps.len() != expected_step_count
        || steps.first().is_none_or(|step| {
            step.kind() != CompactMaskingDisclosureKind::BaseBlindedSourceMessage { epoch }
        })
        || steps.get(1).is_none_or(|step| {
            step.kind() != CompactMaskingDisclosureKind::BaseBlindedSourceRandomness { epoch }
        })
    {
        return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
    }
    for (group_ordinal, step) in steps.iter().skip(2).enumerate() {
        if step.kind()
            != (CompactMaskingDisclosureKind::BaseBlindedMaskGroup {
                epoch,
                group_ordinal: u8::try_from(group_ordinal)
                    .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
            })
        {
            return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
        }
    }
    let output_count = steps.iter().try_fold(0_u64, |count, step| {
        count
            .checked_add(step.output_coordinate_count())
            .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)
    })?;
    let rank = steps.iter().try_fold(0_u64, |count, step| {
        count
            .checked_add(step.conditional_rank())
            .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)
    })?;
    let linear_fiber_count = steps
        .iter()
        .filter(|step| {
            matches!(
                step.image,
                CompactMaskingDisclosureImage::LinearClaimFiber { .. }
            )
        })
        .count();
    if usize::try_from(output_count).ok() != Some(expected_reveal_coordinate_count)
        || rank.checked_add(1) != Some(output_count)
        || linear_fiber_count != 1
        || steps.iter().any(|step| match step.image {
            CompactMaskingDisclosureImage::FullCoordinateSpace => {
                step.conditional_rank() != step.output_coordinate_count()
            }
            CompactMaskingDisclosureImage::LinearClaimFiber { .. } => {
                step.conditional_rank().checked_add(1) != Some(step.output_coordinate_count())
            }
            CompactMaskingDisclosureImage::CoefficientMapImage { .. } => true,
        })
    {
        return Err(CompactMaskingEntropyError::RankFailure);
    }
    Ok(())
}

fn expected_base_reveal_coordinate_count(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    epoch: u8,
) -> Result<usize, CompactMaskingEntropyError> {
    let mut matching_folds = inputs
        .whir_folds
        .iter()
        .filter(|fold| fold.epoch == epoch && fold.batch_ordinal == 3);
    let final_fold = matching_folds
        .next()
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    if matching_folds.next().is_some() {
        return Err(CompactMaskingEntropyError::InvalidContract);
    }
    let mut matching_epochs = inputs
        .whir_epochs
        .iter()
        .filter(|contract| contract.epoch == epoch);
    let epoch_contract = matching_epochs
        .next()
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    if matching_epochs.next().is_some() {
        return Err(CompactMaskingEntropyError::InvalidContract);
    }
    let coordinate_count = epoch_contract
        .external_mask_groups
        .iter()
        .chain(&epoch_contract.internal_mask_groups)
        .try_fold(
            final_fold
                .message_length
                .checked_add(final_fold.hiding_randomness_length)
                .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?,
            |count, group| {
                group
                    .message_length
                    .checked_add(group.randomness_length)
                    .and_then(|lane_count| lane_count.checked_mul(group.width))
                    .and_then(|group_count| count.checked_add(group_count))
                    .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)
            },
        )?;
    usize::try_from(coordinate_count).map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)
}

fn query_leaf_values_for_step(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    kind: CompactMaskingDisclosureKind,
    query_positions: &[u64],
    query_leaves: &[&CompactMaskingQueryLeaf],
    consumed_query_leaves: &mut [bool],
) -> Result<Vec<CompactChallengeField>, CompactMaskingEntropyError> {
    let (geometry, component) = query_component_for_disclosure(inputs, kind)?;
    let expected_value_count_per_leaf =
        usize::try_from(component.field_element_count_per_leaf())
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(
            query_positions
                .len()
                .checked_mul(expected_value_count_per_leaf)
                .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?,
        )
        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    for query_position in query_positions {
        let leaf_ordinal = component
            .first_leaf_ordinal()
            .checked_add(*query_position)
            .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
        let query_leaf_index = query_leaves
            .binary_search_by_key(&(geometry.response_ordinal(), leaf_ordinal), |query_leaf| {
                (query_leaf.response_ordinal, query_leaf.leaf_ordinal)
            })
            .map_err(|_| CompactMaskingEntropyError::MissingTranscriptInput)?;
        let query_leaf = query_leaves[query_leaf_index];
        if consumed_query_leaves
            .get(query_leaf_index)
            .copied()
            .unwrap_or(true)
            || query_leaf.values.len() != expected_value_count_per_leaf
        {
            return Err(CompactMaskingEntropyError::DuplicateTranscriptInput);
        }
        consumed_query_leaves[query_leaf_index] = true;
        values.extend_from_slice(&query_leaf.values);
    }
    Ok(values)
}

fn replay_selected_compact_masking_prefix<'contract>(
    inputs: CompactPublicKeyVerifierInputs<'contract>,
    coefficient_maps: &'contract CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    verified_base_prefix: Option<&CompactVerifiedBaseMaskingPrefix>,
) -> Result<CompactMaskingEntropyAuthority<'contract>, CompactMaskingEntropyError> {
    if completed_messages.is_empty() || completed_messages.len() >= inputs.verifier_moves.len() {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    if verified_base_prefix
        .is_some_and(|prefix| !prefix.authorizes_replay(identity, completed_messages))
    {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    let mut authority = CompactMaskingEntropyAuthority::begin(inputs, coefficient_maps, identity)?;
    for (move_index, message) in completed_messages.iter().enumerate() {
        if let Some(requirement) = authority.next_base_claim_requirement()? {
            let claim = verified_base_prefix
                .map(|prefix| &prefix.claim)
                .filter(|claim| claim.epoch == requirement.epoch)
                .ok_or(CompactMaskingEntropyError::InvalidCoefficientVector)?;
            authority.authorize_next_response(Some(claim))?;
        } else {
            authority.authorize_next_response(None)?;
        }
        let move_ordinal = u32::try_from(move_index)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        let steps = authority
            .ingest_verifier_message(move_ordinal, message)?
            .to_vec();
        match steps.as_slice() {
            [] => {}
            // Source-query values were already bound to the retained oracle by
            // their live opening gate. Their masking image has full row rank,
            // so no value can constrain a later disclosure during replay.
            [source_query_step]
                if matches!(
                    source_query_step.kind(),
                    CompactMaskingDisclosureKind::SourceQueries { .. }
                ) && source_query_step.conditional_rank()
                    == source_query_step.output_coordinate_count() => {}
            _ if verified_base_prefix
                .is_some_and(|prefix| move_index + 1 == prefix.completed_messages.len()) => {}
            _ => return Err(CompactMaskingEntropyError::DisclosureOutOfOrder),
        }
    }
    Ok(authority)
}

fn replay_selected_compact_cfw_masking_prefix<'contract>(
    inputs: CompactPublicKeyVerifierInputs<'contract>,
    coefficient_maps: &'contract CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    completed_messages: &[DecodedFixedUniformVerifierMessage],
) -> Result<CompactMaskingEntropyAuthority<'contract>, CompactMaskingEntropyError> {
    let cfw_round_count = inputs.cfw_configuration.geometry().sumcheck_round_count();
    if !(3..=cfw_round_count.saturating_add(3)).contains(&completed_messages.len()) {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    let mut authority = CompactMaskingEntropyAuthority::begin(inputs, coefficient_maps, identity)?;
    for (move_index, message) in completed_messages.iter().enumerate() {
        let steps = authority.authorize_next_response(None)?;
        let valid_response = match move_index {
            0 | 1 => steps.is_empty(),
            2 => matches!(
                steps,
                [cross_epoch_step, auxiliary_step]
                    if cross_epoch_step.kind()
                        == CompactMaskingDisclosureKind::CrossEpochExplicitPoint
                        && auxiliary_step.kind()
                            == CompactMaskingDisclosureKind::CfwOuterAuxiliary
            ),
            _ => {
                let round_ordinal = u32::try_from(move_index - 3)
                    .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
                matches!(
                    steps,
                    [round_step]
                        if round_step.kind()
                            == CompactMaskingDisclosureKind::CfwOuterRound { round_ordinal }
                )
            }
        };
        if !valid_response {
            return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
        }
        let move_ordinal = u32::try_from(move_index)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        if !authority
            .ingest_verifier_message(move_ordinal, message)?
            .is_empty()
        {
            return Err(CompactMaskingEntropyError::DisclosureOutOfOrder);
        }
    }
    Ok(authority)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactMaskingEntropyError {
    ArithmeticOverflow,
    InvalidContract,
    InvalidCoefficientMap,
    MissingTranscriptInput,
    DuplicateTranscriptInput,
    InvalidChallenge,
    InvalidQuerySet,
    InvalidCoefficientVector,
    RankFailure,
    DisclosureOutOfOrder,
    #[cfg(test)]
    AttemptIdentityMismatch,
    #[cfg(test)]
    CertificateMismatch,
    WrongAuthorityPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateSource {
    CrossEpochMessages,
    CrossEpochEncoding,
    CfwInnerMessages,
    CfwInnerEncoding,
    CfwOuterMessages,
    CfwOuterEncoding,
    WhirSourceEncoding { epoch: u8, source_ordinal: u8 },
    WhirSumcheckMessages { epoch: u8, batch_ordinal: u8 },
    WhirMaskEncoding { epoch: u8, group_ordinal: u8 },
    WhirFreshSourceMessage { epoch: u8 },
    WhirFreshSourceEncoding { epoch: u8 },
    WhirFreshMaskMessage { epoch: u8, group_ordinal: u8 },
    WhirFreshMaskEncoding { epoch: u8, group_ordinal: u8 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceState {
    source: PrivateSource,
    dimension: u64,
    rank: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingStep {
    verifier_move_ordinal: u32,
    intra_move_ordinal: u32,
    kind: CompactMaskingDisclosureKind,
    source_rank_increments: Vec<(PrivateSource, u64)>,
    output_coordinate_count: u64,
    image: CompactMaskingDisclosureImage,
}

#[cfg(test)]
pub(crate) fn certify_compact_masking_entropy(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    transcript: &CompactMaskingEntropyTranscript,
) -> Result<CompactMaskingEntropyCertificate, CompactMaskingEntropyError> {
    certify_compact_masking_entropy_with_sources(inputs, coefficient_maps, transcript)
        .map(|(certificate, _)| certificate)
}

#[cfg(test)]
fn certify_compact_masking_entropy_with_sources(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    transcript: &CompactMaskingEntropyTranscript,
) -> Result<(CompactMaskingEntropyCertificate, Vec<SourceState>), CompactMaskingEntropyError> {
    coefficient_maps
        .check()
        .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientMap)?;
    if inputs
        .canonical_source_hash()
        .map_err(|_| CompactMaskingEntropyError::InvalidContract)?
        .into_bytes()
        != coefficient_maps.certificate_digest()
    {
        return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
    }
    validate_transcript_inputs(inputs, transcript)?;
    validate_rank_map_coverage(coefficient_maps)?;

    let mut sources = derive_private_sources(inputs)?;
    let mut pending = derive_scalar_steps(inputs, coefficient_maps, transcript)?;
    append_query_steps(inputs, coefficient_maps, transcript, &mut pending)?;
    append_base_reveal_steps(inputs, transcript, &mut pending)?;
    pending.sort_by_key(|step| (step.verifier_move_ordinal, step.intra_move_ordinal));

    let private_coordinate_count = sources
        .iter()
        .try_fold(0_u64, |sum, source| checked_add(sum, source.dimension))?;
    let mut cumulative_rank = 0_u64;
    let mut steps = Vec::with_capacity(pending.len());
    for pending_step in pending {
        let conditional_rank = pending_step_conditional_rank(&pending_step)?;
        for (source, increment) in &pending_step.source_rank_increments {
            let state = sources
                .iter_mut()
                .find(|state| state.source == *source)
                .ok_or(CompactMaskingEntropyError::InvalidContract)?;
            state.rank = checked_add(state.rank, *increment)?;
            if state.rank > state.dimension {
                return Err(CompactMaskingEntropyError::RankFailure);
            }
        }
        cumulative_rank = checked_add(cumulative_rank, conditional_rank)?;
        let ordinal = u32::try_from(steps.len())
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        steps.push(CompactMaskingEntropyStep {
            ordinal,
            verifier_move_ordinal: pending_step.verifier_move_ordinal,
            kind: pending_step.kind,
            output_coordinate_count: pending_step.output_coordinate_count,
            image: pending_step.image,
            conditional_rank,
            cumulative_rank,
            residual_entropy_dimension: private_coordinate_count
                .checked_sub(cumulative_rank)
                .ok_or(CompactMaskingEntropyError::RankFailure)?,
        });
    }
    let summed_rank = sources
        .iter()
        .try_fold(0_u64, |sum, source| checked_add(sum, source.rank))?;
    if summed_rank != cumulative_rank {
        return Err(CompactMaskingEntropyError::RankFailure);
    }
    let shared_cross_epoch_query_overlap = shared_cross_query_overlap(inputs, transcript)?;
    let disclosure_digest = hash_steps(&steps);
    let contract_binding = hash_contract_binding(inputs, coefficient_maps, &disclosure_digest)?;
    Ok((
        CompactMaskingEntropyCertificate {
            steps,
            private_coordinate_count,
            joint_disclosure_rank: cumulative_rank,
            residual_conditional_entropy_dimension: private_coordinate_count - cumulative_rank,
            shared_cross_epoch_query_overlap,
            disclosure_digest,
            contract_binding,
            coefficient_map_binding: coefficient_maps.certificate_digest(),
        },
        sources,
    ))
}

#[cfg(test)]
fn validate_transcript_inputs(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    transcript: &CompactMaskingEntropyTranscript,
) -> Result<(), CompactMaskingEntropyError> {
    let cfw_round_count = inputs.cfw_configuration.geometry().sumcheck_round_count();
    if transcript.cfw_constraint_combining_challenge.is_none()
        || transcript.cfw_equality_point.len() != cfw_round_count
        || transcript.cfw_round_challenges.len() != cfw_round_count
        || transcript.cfw_round_challenges.is_empty()
        || !compact_cfw_final_challenge_is_allowed(
            *transcript
                .cfw_round_challenges
                .last()
                .ok_or(CompactMaskingEntropyError::MissingTranscriptInput)?,
        )
    {
        return Err(CompactMaskingEntropyError::InvalidChallenge);
    }

    for (move_index, verifier_move) in inputs.verifier_moves.iter().enumerate() {
        if usize::try_from(verifier_move.ordinal).ok() != Some(move_index) {
            return Err(CompactMaskingEntropyError::InvalidContract);
        }
        for (group_index, geometry) in verifier_move
            .message_geometry
            .distinct_query_groups()
            .iter()
            .enumerate()
        {
            let set = unique_query_set(
                transcript,
                verifier_move.ordinal,
                u32::try_from(group_index)
                    .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
            )?;
            if u64::try_from(set.indices.len()).ok() != Some(geometry.query_count())
                || set
                    .indices
                    .iter()
                    .any(|index| *index >= geometry.domain_cardinality())
                || set.indices.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(CompactMaskingEntropyError::InvalidQuerySet);
            }
        }
    }
    let expected_query_set_count =
        inputs
            .verifier_moves
            .iter()
            .try_fold(0_usize, |sum, move_| {
                sum.checked_add(move_.message_geometry.distinct_query_groups().len())
                    .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)
            })?;
    if transcript.query_sets.len() != expected_query_set_count {
        return Err(CompactMaskingEntropyError::DuplicateTranscriptInput);
    }

    let mut expected_sumcheck_count = 0_usize;
    for epoch in inputs.whir_epochs {
        for group in epoch
            .internal_mask_groups
            .iter()
            .filter(|group| group.role_tag == 4)
        {
            expected_sumcheck_count += 1;
            let challenges = unique_sumcheck_challenges(transcript, epoch.epoch, group.coordinate)?;
            if u64::try_from(challenges.len()).ok() != Some(group.width) {
                return Err(CompactMaskingEntropyError::InvalidChallenge);
            }
        }
    }
    if transcript.sumcheck_challenges.len() != expected_sumcheck_count {
        return Err(CompactMaskingEntropyError::DuplicateTranscriptInput);
    }

    if inputs.whir_epochs.len() != 2 || transcript.base_fresh_claims.len() != 2 {
        return Err(CompactMaskingEntropyError::MissingTranscriptInput);
    }
    for epoch in inputs.whir_epochs {
        let claim = unique_base_claim(transcript, epoch.epoch)?;
        if u64::try_from(claim.coefficients.len()).ok()
            != Some(base_fresh_message_dimension(epoch)?)
            || claim
                .coefficients
                .iter()
                .all(|coefficient| *coefficient == CompactChallengeField::ZERO)
        {
            return Err(CompactMaskingEntropyError::InvalidCoefficientVector);
        }
    }
    Ok(())
}

fn validate_rank_map_coverage(
    certificate: &CompactMaskingCoefficientMapCertificate,
) -> Result<(), CompactMaskingEntropyError> {
    for map in certificate.maps() {
        let valid = match (&map.projection, map.surjectivity) {
            (
                CompactCoefficientProjection::FoldedReedSolomonSource { .. }
                | CompactCoefficientProjection::CarriedMaskReedSolomon { .. },
                CompactSurjectivityWitness::ReedSolomonRandomnessMinor { .. },
            ) => true,
            (
                CompactCoefficientProjection::CfwOuterTranscript { .. },
                CompactSurjectivityWitness::CfwOuterFullColumnRank { .. },
            ) => true,
            (
                CompactCoefficientProjection::CfwInnerTerminal { .. },
                CompactSurjectivityWitness::CfwTerminalDisjointRolePivots { .. },
            ) => true,
            (
                CompactCoefficientProjection::CrossEpochExplicitPoint { .. },
                CompactSurjectivityWitness::CrossEpochTwoMaskCorrection,
            ) => true,
            (
                CompactCoefficientProjection::WhirSumcheckTranscript { .. },
                CompactSurjectivityWitness::WhirSumcheckConstantMinor { .. },
            ) => true,
            (
                CompactCoefficientProjection::WhirBaseCaseClaim { dependencies },
                CompactSurjectivityWitness::InheritedFreshCoordinateCovector { dependency_count },
            ) => u64::try_from(dependencies.len()).ok() == Some(dependency_count),
            _ => !matches!(
                map.projection,
                CompactCoefficientProjection::FoldedReedSolomonSource { .. }
                    | CompactCoefficientProjection::CarriedMaskReedSolomon { .. }
                    | CompactCoefficientProjection::CfwOuterTranscript { .. }
                    | CompactCoefficientProjection::CfwInnerTerminal { .. }
                    | CompactCoefficientProjection::CrossEpochExplicitPoint { .. }
                    | CompactCoefficientProjection::WhirSumcheckTranscript { .. }
                    | CompactCoefficientProjection::WhirBaseCaseClaim { .. }
            ),
        };
        if !valid {
            return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
        }
    }
    Ok(())
}

fn derive_private_sources(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
) -> Result<Vec<SourceState>, CompactMaskingEntropyError> {
    let cfw = inputs.cfw_configuration.geometry();
    let cfw_round_count = u64::try_from(cfw.sumcheck_round_count())
        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    let mut sources = vec![
        source(PrivateSource::CrossEpochMessages, 2),
        source(
            PrivateSource::CfwInnerMessages,
            checked_product(&[cfw_round_count, COMPACT_CFW_MATRIX_COUNT as u64, 2])?,
        ),
        source(
            PrivateSource::CfwOuterMessages,
            checked_product(&[cfw_round_count, CFW_OUTER_MASK_MESSAGE_LENGTH_U64])?,
        ),
    ];

    let mut saw_shared_encoding = false;
    for epoch in inputs.whir_epochs {
        let folds = epoch_folds(inputs, epoch.epoch)?;
        for fold in folds {
            sources.push(source(
                PrivateSource::WhirSourceEncoding {
                    epoch: epoch.epoch,
                    source_ordinal: fold.batch_ordinal,
                },
                checked_product(&[fold.oracle_width, fold.hiding_randomness_length])?,
            ));
        }
        for (group_index, group) in epoch
            .external_mask_groups
            .iter()
            .chain(&epoch.internal_mask_groups)
            .enumerate()
        {
            match group.role_tag {
                1 if group.committed_encoding_source == 1 => {
                    if saw_shared_encoding {
                        return Err(CompactMaskingEntropyError::InvalidContract);
                    }
                    sources.push(source(
                        PrivateSource::CrossEpochEncoding,
                        checked_product(&[group.width, group.randomness_length])?,
                    ));
                    saw_shared_encoding = true;
                }
                1 => {}
                2 => sources.push(source(
                    PrivateSource::CfwInnerEncoding,
                    checked_product(&[group.width, group.randomness_length])?,
                )),
                3 => sources.push(source(
                    PrivateSource::CfwOuterEncoding,
                    checked_product(&[group.width, group.randomness_length])?,
                )),
                4 | 5 => sources.push(source(
                    PrivateSource::WhirMaskEncoding {
                        epoch: epoch.epoch,
                        group_ordinal: u8::try_from(group_index)
                            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
                    },
                    checked_product(&[group.width, group.randomness_length])?,
                )),
                _ => return Err(CompactMaskingEntropyError::InvalidContract),
            }
            if group.role_tag == 4 {
                sources.push(source(
                    PrivateSource::WhirSumcheckMessages {
                        epoch: epoch.epoch,
                        batch_ordinal: group.coordinate,
                    },
                    checked_product(&[group.width, group.message_length])?,
                ));
            }
        }
        let final_fold = folds
            .last()
            .ok_or(CompactMaskingEntropyError::InvalidContract)?;
        sources.push(source(
            PrivateSource::WhirFreshSourceMessage { epoch: epoch.epoch },
            final_fold.message_length,
        ));
        sources.push(source(
            PrivateSource::WhirFreshSourceEncoding { epoch: epoch.epoch },
            final_fold.hiding_randomness_length,
        ));
        for (group_index, group) in epoch
            .external_mask_groups
            .iter()
            .chain(&epoch.internal_mask_groups)
            .enumerate()
        {
            let group_ordinal = u8::try_from(group_index)
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
            sources.push(source(
                PrivateSource::WhirFreshMaskMessage {
                    epoch: epoch.epoch,
                    group_ordinal,
                },
                checked_product(&[group.width, group.message_length])?,
            ));
            sources.push(source(
                PrivateSource::WhirFreshMaskEncoding {
                    epoch: epoch.epoch,
                    group_ordinal,
                },
                checked_product(&[group.width, group.randomness_length])?,
            ));
        }
    }
    if !saw_shared_encoding {
        return Err(CompactMaskingEntropyError::InvalidContract);
    }
    Ok(sources)
}

#[cfg(test)]
fn derive_scalar_steps(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    transcript: &CompactMaskingEntropyTranscript,
) -> Result<Vec<PendingStep>, CompactMaskingEntropyError> {
    let cfw_round_count = transcript.cfw_round_challenges.len();
    let cfw_outer_incremental_ranks =
        cfw_outer_incremental_ranks(coefficient_maps, &transcript.cfw_round_challenges)?;
    let cfw_inner_rank =
        cfw_inner_terminal_rank(coefficient_maps, &transcript.cfw_round_challenges)?;
    let cross_rank = cross_epoch_rank(coefficient_maps, inputs)?;
    let mut steps = Vec::new();
    for ((geometry, roles), response_index) in inputs
        .response_merkle_geometries
        .iter()
        .zip(inputs.response_component_roles)
        .zip(0_usize..)
    {
        if geometry.components().len() != roles.len() {
            return Err(CompactMaskingEntropyError::InvalidContract);
        }
        let verifier_move_ordinal = u32::try_from(response_index)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        for (component_index, (component, role)) in
            geometry.components().iter().zip(roles).enumerate()
        {
            if !matches!(
                component.query_selection(),
                CompactResponseQuerySelection::EveryLeaf
            ) {
                continue;
            }
            let intra = simulator_intra_move_ordinal(
                u32::try_from(component_index)
                    .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
                role.role_tag,
            )?;
            match role.role_tag {
                6 => {
                    require_component(component, 3, 1)?;
                    steps.push(pending_with_image(
                        verifier_move_ordinal,
                        intra,
                        CompactMaskingDisclosureKind::CrossEpochExplicitPoint,
                        PrivateSource::CrossEpochMessages,
                        3,
                        cross_rank,
                        coefficient_map_image(
                            coefficient_maps,
                            CompactMaskingViewRole::ExplicitPoint,
                            0,
                            0,
                            0,
                            0,
                        )?,
                    ));
                }
                7 => {
                    require_component(component, 1, 1)?;
                    steps.push(pending_with_image(
                        verifier_move_ordinal,
                        intra,
                        CompactMaskingDisclosureKind::CfwOuterAuxiliary,
                        PrivateSource::CfwOuterMessages,
                        1,
                        cfw_outer_incremental_ranks[0],
                        coefficient_map_image(
                            coefficient_maps,
                            CompactMaskingViewRole::Sumcheck,
                            0,
                            0,
                            1,
                            0,
                        )?,
                    ));
                }
                8 => {
                    require_component(component, CFW_OUTER_MASK_MESSAGE_LENGTH_U64, 1)?;
                    let round = usize::try_from(role.round_ordinal)
                        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
                    if round >= cfw_round_count {
                        return Err(CompactMaskingEntropyError::InvalidContract);
                    }
                    steps.push(pending_with_image(
                        verifier_move_ordinal,
                        intra,
                        CompactMaskingDisclosureKind::CfwOuterRound {
                            round_ordinal: role.round_ordinal,
                        },
                        PrivateSource::CfwOuterMessages,
                        CFW_OUTER_MASK_MESSAGE_LENGTH_U64,
                        cfw_outer_incremental_ranks[round + 1],
                        coefficient_map_image(
                            coefficient_maps,
                            CompactMaskingViewRole::Sumcheck,
                            0,
                            0,
                            1,
                            checked_add(
                                1,
                                checked_product(&[
                                    u64::from(role.round_ordinal),
                                    CFW_OUTER_MASK_MESSAGE_LENGTH_U64,
                                ])?,
                            )?,
                        )?,
                    ));
                }
                9 => {
                    require_component(
                        component,
                        u64::try_from(cfw_round_count)
                            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
                        1,
                    )?;
                    steps.push(pending_with_image(
                        verifier_move_ordinal,
                        intra,
                        CompactMaskingDisclosureKind::CfwOuterEvaluations,
                        PrivateSource::CfwOuterMessages,
                        u64::try_from(cfw_round_count)
                            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
                        *cfw_outer_incremental_ranks
                            .last()
                            .ok_or(CompactMaskingEntropyError::RankFailure)?,
                        coefficient_map_image(
                            coefficient_maps,
                            CompactMaskingViewRole::Sumcheck,
                            0,
                            0,
                            1,
                            checked_add(
                                1,
                                checked_product(&[
                                    u64::try_from(cfw_round_count).map_err(|_| {
                                        CompactMaskingEntropyError::ArithmeticOverflow
                                    })?,
                                    CFW_OUTER_MASK_MESSAGE_LENGTH_U64,
                                ])?,
                            )?,
                        )?,
                    ));
                }
                10 => {
                    require_component(component, COMPACT_CFW_MATRIX_COUNT as u64, 1)?;
                    steps.push(pending_with_image(
                        verifier_move_ordinal,
                        intra,
                        CompactMaskingDisclosureKind::CfwInnerTerminal,
                        PrivateSource::CfwInnerMessages,
                        COMPACT_CFW_MATRIX_COUNT as u64,
                        cfw_inner_rank,
                        coefficient_map_image(
                            coefficient_maps,
                            CompactMaskingViewRole::Terminal,
                            0,
                            0,
                            1,
                            0,
                        )?,
                    ));
                }
                12 => {
                    require_component(component, 1, 1)?;
                    let ranks = sumcheck_incremental_ranks(
                        coefficient_maps,
                        role,
                        unique_sumcheck_challenges(transcript, role.epoch, role.batch_ordinal)?,
                    )?;
                    steps.push(pending_with_image(
                        verifier_move_ordinal,
                        intra,
                        CompactMaskingDisclosureKind::WhirSumcheckAuxiliary {
                            epoch: role.epoch,
                            batch_ordinal: role.batch_ordinal,
                        },
                        PrivateSource::WhirSumcheckMessages {
                            epoch: role.epoch,
                            batch_ordinal: role.batch_ordinal,
                        },
                        1,
                        ranks[0],
                        coefficient_map_image(
                            coefficient_maps,
                            CompactMaskingViewRole::Sumcheck,
                            role.epoch,
                            role.batch_ordinal,
                            0,
                            0,
                        )?,
                    ));
                }
                13 => {
                    require_component(component, 2, 1)?;
                    let ranks = sumcheck_incremental_ranks(
                        coefficient_maps,
                        role,
                        unique_sumcheck_challenges(transcript, role.epoch, role.batch_ordinal)?,
                    )?;
                    let round = usize::try_from(role.round_ordinal)
                        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
                    let increment = *ranks
                        .get(round + 1)
                        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
                    steps.push(pending_with_image(
                        verifier_move_ordinal,
                        intra,
                        CompactMaskingDisclosureKind::WhirSumcheckRound {
                            epoch: role.epoch,
                            batch_ordinal: role.batch_ordinal,
                            round_ordinal: role.round_ordinal,
                        },
                        PrivateSource::WhirSumcheckMessages {
                            epoch: role.epoch,
                            batch_ordinal: role.batch_ordinal,
                        },
                        2,
                        increment,
                        coefficient_map_image(
                            coefficient_maps,
                            CompactMaskingViewRole::Sumcheck,
                            role.epoch,
                            role.batch_ordinal,
                            0,
                            checked_add(1, checked_product(&[u64::from(role.round_ordinal), 2])?)?,
                        )?,
                    ));
                }
                18 => {
                    require_component(component, 1, 1)?;
                    let claim = unique_base_claim(transcript, role.epoch)?;
                    let rank = u64::from(
                        claim
                            .coefficients
                            .iter()
                            .any(|coefficient| *coefficient != CompactChallengeField::ZERO),
                    );
                    steps.push(PendingStep {
                        verifier_move_ordinal,
                        intra_move_ordinal: intra,
                        kind: CompactMaskingDisclosureKind::BaseFreshClaim { epoch: role.epoch },
                        source_rank_increments: claim_pivot_source(inputs, claim)?
                            .map(|source| vec![(source, rank)])
                            .unwrap_or_default(),
                        output_coordinate_count: 1,
                        image: CompactMaskingDisclosureImage::FullCoordinateSpace,
                    });
                }
                19..=22 => {}
                _ => return Err(CompactMaskingEntropyError::InvalidContract),
            }
        }
    }
    Ok(steps)
}

fn derive_available_scalar_steps(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    transcript: &CompactMaskingEntropyTranscript,
    move_ordinal: usize,
) -> Result<Vec<PendingStep>, CompactMaskingEntropyError> {
    let geometry = inputs
        .response_merkle_geometries
        .get(move_ordinal)
        .ok_or(CompactMaskingEntropyError::WrongAuthorityPhase)?;
    let roles = inputs
        .response_component_roles
        .get(move_ordinal)
        .ok_or(CompactMaskingEntropyError::WrongAuthorityPhase)?;
    if geometry.components().len() != roles.len() {
        return Err(CompactMaskingEntropyError::InvalidContract);
    }
    let verifier_move_ordinal =
        u32::try_from(move_ordinal).map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    let cfw_round_count = inputs.cfw_configuration.geometry().sumcheck_round_count();
    let mut steps = Vec::new();
    for (component_index, (component, role)) in geometry.components().iter().zip(roles).enumerate()
    {
        if !matches!(
            component.query_selection(),
            CompactResponseQuerySelection::EveryLeaf
        ) {
            continue;
        }
        let intra = simulator_intra_move_ordinal(
            u32::try_from(component_index)
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
            role.role_tag,
        )?;
        match role.role_tag {
            6 => {
                require_component(component, 3, 1)?;
                steps.push(pending_with_image(
                    verifier_move_ordinal,
                    intra,
                    CompactMaskingDisclosureKind::CrossEpochExplicitPoint,
                    PrivateSource::CrossEpochMessages,
                    3,
                    2,
                    coefficient_map_image(
                        coefficient_maps,
                        CompactMaskingViewRole::ExplicitPoint,
                        0,
                        0,
                        0,
                        0,
                    )?,
                ));
            }
            7 => {
                require_component(component, 1, 1)?;
                steps.push(pending_with_image(
                    verifier_move_ordinal,
                    intra,
                    CompactMaskingDisclosureKind::CfwOuterAuxiliary,
                    PrivateSource::CfwOuterMessages,
                    1,
                    1,
                    coefficient_map_image(
                        coefficient_maps,
                        CompactMaskingViewRole::Sumcheck,
                        0,
                        0,
                        1,
                        0,
                    )?,
                ));
            }
            8 => {
                require_component(component, CFW_OUTER_MASK_MESSAGE_LENGTH_U64, 1)?;
                if usize::try_from(role.round_ordinal).ok()
                    != Some(transcript.cfw_round_challenges.len())
                    || transcript.cfw_round_challenges.len() >= cfw_round_count
                {
                    return Err(CompactMaskingEntropyError::InvalidChallenge);
                }
                steps.push(pending_with_image(
                    verifier_move_ordinal,
                    intra,
                    CompactMaskingDisclosureKind::CfwOuterRound {
                        round_ordinal: role.round_ordinal,
                    },
                    PrivateSource::CfwOuterMessages,
                    CFW_OUTER_MASK_MESSAGE_LENGTH_U64,
                    CFW_OUTER_MASK_MESSAGE_LENGTH_U64 - 1,
                    coefficient_map_image(
                        coefficient_maps,
                        CompactMaskingViewRole::Sumcheck,
                        0,
                        0,
                        1,
                        checked_add(
                            1,
                            checked_product(&[
                                u64::from(role.round_ordinal),
                                CFW_OUTER_MASK_MESSAGE_LENGTH_U64,
                            ])?,
                        )?,
                    )?,
                ));
            }
            9 => {
                require_component(component, cfw_round_count as u64, 1)?;
                if transcript.cfw_round_challenges.len() != cfw_round_count {
                    return Err(CompactMaskingEntropyError::InvalidChallenge);
                }
                let final_increment = *cfw_outer_incremental_ranks(
                    coefficient_maps,
                    &transcript.cfw_round_challenges,
                )?
                .last()
                .ok_or(CompactMaskingEntropyError::RankFailure)?;
                steps.push(pending_with_image(
                    verifier_move_ordinal,
                    intra,
                    CompactMaskingDisclosureKind::CfwOuterEvaluations,
                    PrivateSource::CfwOuterMessages,
                    cfw_round_count as u64,
                    final_increment,
                    coefficient_map_image(
                        coefficient_maps,
                        CompactMaskingViewRole::Sumcheck,
                        0,
                        0,
                        1,
                        checked_add(
                            1,
                            checked_product(&[
                                cfw_round_count as u64,
                                CFW_OUTER_MASK_MESSAGE_LENGTH_U64,
                            ])?,
                        )?,
                    )?,
                ));
            }
            10 => {
                require_component(component, COMPACT_CFW_MATRIX_COUNT as u64, 1)?;
                if transcript.cfw_round_challenges.len() != cfw_round_count
                    || !compact_cfw_final_challenge_is_allowed(
                        *transcript
                            .cfw_round_challenges
                            .last()
                            .ok_or(CompactMaskingEntropyError::InvalidChallenge)?,
                    )
                {
                    return Err(CompactMaskingEntropyError::InvalidChallenge);
                }
                steps.push(pending_with_image(
                    verifier_move_ordinal,
                    intra,
                    CompactMaskingDisclosureKind::CfwInnerTerminal,
                    PrivateSource::CfwInnerMessages,
                    COMPACT_CFW_MATRIX_COUNT as u64,
                    COMPACT_CFW_MATRIX_COUNT as u64,
                    coefficient_map_image(
                        coefficient_maps,
                        CompactMaskingViewRole::Terminal,
                        0,
                        0,
                        1,
                        0,
                    )?,
                ));
            }
            12 => {
                require_component(component, 1, 1)?;
                let current = transcript
                    .sumcheck_challenges
                    .iter()
                    .find(|record| {
                        record.epoch == role.epoch && record.batch_ordinal == role.batch_ordinal
                    })
                    .map_or(0, |record| record.challenges.len());
                if current != 0 {
                    return Err(CompactMaskingEntropyError::InvalidChallenge);
                }
                steps.push(pending_with_image(
                    verifier_move_ordinal,
                    intra,
                    CompactMaskingDisclosureKind::WhirSumcheckAuxiliary {
                        epoch: role.epoch,
                        batch_ordinal: role.batch_ordinal,
                    },
                    PrivateSource::WhirSumcheckMessages {
                        epoch: role.epoch,
                        batch_ordinal: role.batch_ordinal,
                    },
                    1,
                    1,
                    coefficient_map_image(
                        coefficient_maps,
                        CompactMaskingViewRole::Sumcheck,
                        role.epoch,
                        role.batch_ordinal,
                        0,
                        0,
                    )?,
                ));
            }
            13 => {
                require_component(component, 2, 1)?;
                let count = transcript
                    .sumcheck_challenges
                    .iter()
                    .find(|record| {
                        record.epoch == role.epoch && record.batch_ordinal == role.batch_ordinal
                    })
                    .map_or(0, |record| record.challenges.len());
                if usize::try_from(role.round_ordinal).ok() != Some(count) {
                    return Err(CompactMaskingEntropyError::InvalidChallenge);
                }
                steps.push(pending_with_image(
                    verifier_move_ordinal,
                    intra,
                    CompactMaskingDisclosureKind::WhirSumcheckRound {
                        epoch: role.epoch,
                        batch_ordinal: role.batch_ordinal,
                        round_ordinal: role.round_ordinal,
                    },
                    PrivateSource::WhirSumcheckMessages {
                        epoch: role.epoch,
                        batch_ordinal: role.batch_ordinal,
                    },
                    2,
                    2,
                    coefficient_map_image(
                        coefficient_maps,
                        CompactMaskingViewRole::Sumcheck,
                        role.epoch,
                        role.batch_ordinal,
                        0,
                        checked_add(1, checked_product(&[u64::from(role.round_ordinal), 2])?)?,
                    )?,
                ));
            }
            18 => {
                require_component(component, 1, 1)?;
                let claim = unique_base_claim(transcript, role.epoch)?;
                steps.push(PendingStep {
                    verifier_move_ordinal,
                    intra_move_ordinal: intra,
                    kind: CompactMaskingDisclosureKind::BaseFreshClaim { epoch: role.epoch },
                    source_rank_increments: claim_pivot_source(inputs, claim)?
                        .map(|source| vec![(source, 1)])
                        .unwrap_or_default(),
                    output_coordinate_count: 1,
                    image: CompactMaskingDisclosureImage::FullCoordinateSpace,
                });
            }
            19..=21 => {}
            22 => {}
            _ => return Err(CompactMaskingEntropyError::InvalidContract),
        }
    }
    if roles.iter().any(|role| (19..=21).contains(&role.role_tag)) {
        let epoch = roles
            .iter()
            .find(|role| role.role_tag == 19)
            .ok_or(CompactMaskingEntropyError::InvalidContract)?
            .epoch;
        append_base_reveal_steps_for_epoch(inputs, transcript, epoch, &mut steps)?;
    }
    steps.sort_by_key(|step| step.intra_move_ordinal);
    Ok(steps)
}

fn append_streaming_steps(
    sources: &mut [SourceState],
    steps: &mut Vec<CompactMaskingEntropyStep>,
    pending: Vec<PendingStep>,
) -> Result<(), CompactMaskingEntropyError> {
    let private_coordinate_count = sources
        .iter()
        .try_fold(0_u64, |sum, source| checked_add(sum, source.dimension))?;
    let mut cumulative_rank = steps.last().map_or(0, |step| step.cumulative_rank);
    for pending in pending {
        let conditional_rank = pending_step_conditional_rank(&pending)?;
        for (source, increment) in &pending.source_rank_increments {
            let state = sources
                .iter_mut()
                .find(|state| state.source == *source)
                .ok_or(CompactMaskingEntropyError::InvalidContract)?;
            state.rank = checked_add(state.rank, *increment)?;
            if state.rank > state.dimension {
                return Err(CompactMaskingEntropyError::RankFailure);
            }
        }
        cumulative_rank = checked_add(cumulative_rank, conditional_rank)?;
        if cumulative_rank > private_coordinate_count {
            return Err(CompactMaskingEntropyError::RankFailure);
        }
        steps.push(CompactMaskingEntropyStep {
            ordinal: u32::try_from(steps.len())
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
            verifier_move_ordinal: pending.verifier_move_ordinal,
            kind: pending.kind,
            output_coordinate_count: pending.output_coordinate_count,
            image: pending.image,
            conditional_rank,
            cumulative_rank,
            residual_entropy_dimension: private_coordinate_count - cumulative_rank,
        });
    }
    Ok(())
}

fn coefficient_map_image(
    certificate: &CompactMaskingCoefficientMapCertificate,
    role: CompactMaskingViewRole,
    epoch: u8,
    batch_ordinal: u8,
    coordinate: u32,
    first_output_coordinate: u64,
) -> Result<CompactMaskingDisclosureImage, CompactMaskingEntropyError> {
    let map_ordinal = certificate
        .maps()
        .iter()
        .position(|map| {
            map.coordinate.role == role
                && map.coordinate.epoch == epoch
                && map.coordinate.batch_ordinal == batch_ordinal
                && map.coordinate.coordinate == coordinate
        })
        .ok_or(CompactMaskingEntropyError::InvalidCoefficientMap)?;
    Ok(CompactMaskingDisclosureImage::CoefficientMapImage {
        map_ordinal,
        first_output_coordinate,
    })
}

#[cfg(test)]
fn append_query_steps(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    transcript: &CompactMaskingEntropyTranscript,
    steps: &mut Vec<PendingStep>,
) -> Result<(), CompactMaskingEntropyError> {
    append_query_steps_with_move_filter(inputs, coefficient_maps, transcript, None, steps)
}

fn append_query_steps_with_move_filter(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    transcript: &CompactMaskingEntropyTranscript,
    move_ordinal_filter: Option<u32>,
    steps: &mut Vec<PendingStep>,
) -> Result<(), CompactMaskingEntropyError> {
    for (geometry, roles) in inputs
        .response_merkle_geometries
        .iter()
        .zip(inputs.response_component_roles)
    {
        for (component_index, (component, role)) in
            geometry.components().iter().zip(roles).enumerate()
        {
            if matches!(
                component.query_selection(),
                CompactResponseQuerySelection::EveryLeaf | CompactResponseQuerySelection::Unqueried
            ) {
                continue;
            }
            let intra = 10_000_u32
                .checked_add(
                    u32::try_from(component_index)
                        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
                )
                .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
            let query_refs = component_query_refs(component);
            if move_ordinal_filter.is_some()
                && !query_refs
                    .iter()
                    .any(|query_ref| Some(query_ref.0) == move_ordinal_filter)
            {
                continue;
            }
            let first_move = query_refs
                .first()
                .ok_or(CompactMaskingEntropyError::InvalidContract)?
                .0;
            match role.role_tag {
                1 | 3 | 14 => {
                    let (source_epoch, source_ordinal) = source_coordinate_for_role(role)?;
                    let query = unique_query_set(transcript, query_refs[0].0, query_refs[0].1)?;
                    let map_ordinal = coefficient_maps
                        .maps()
                        .iter()
                        .position(|map| {
                            map.coordinate.role == CompactMaskingViewRole::Source
                                && map.coordinate.epoch == source_epoch
                                && map.coordinate.batch_ordinal == source_ordinal
                        })
                        .ok_or(CompactMaskingEntropyError::InvalidCoefficientMap)?;
                    let map = &coefficient_maps.maps()[map_ordinal];
                    let CompactCoefficientProjection::FoldedReedSolomonSource {
                        lane_count,
                        message_length_per_lane,
                        randomness_length_per_lane,
                        domain_size,
                        ..
                    } = map.projection
                    else {
                        return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
                    };
                    let rank = structured_reed_solomon_rank(
                        message_length_per_lane,
                        randomness_length_per_lane,
                        domain_size,
                        lane_count,
                        &query.indices,
                    )?;
                    steps.push(pending_with_image(
                        first_move,
                        intra,
                        CompactMaskingDisclosureKind::SourceQueries {
                            epoch: source_epoch,
                            source_ordinal,
                        },
                        PrivateSource::WhirSourceEncoding {
                            epoch: source_epoch,
                            source_ordinal,
                        },
                        rank,
                        rank,
                        CompactMaskingDisclosureImage::CoefficientMapImage {
                            map_ordinal,
                            first_output_coordinate: 0,
                        },
                    ));
                }
                2 | 4 | 5 | 11 | 15 => {
                    append_carried_mask_query_steps(
                        CarriedMaskQueryContext {
                            inputs,
                            coefficient_maps,
                            transcript,
                            move_ordinal_filter,
                        },
                        component,
                        role,
                        intra,
                        steps,
                    )?;
                }
                16 => {
                    let query = unique_query_set(transcript, query_refs[0].0, query_refs[0].1)?;
                    let final_fold = epoch_folds(inputs, role.epoch)?
                        .last()
                        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
                    let rank = structured_reed_solomon_rank(
                        final_fold.message_length,
                        final_fold.hiding_randomness_length,
                        final_fold.block_length,
                        1,
                        &query.indices,
                    )?;
                    steps.push(PendingStep {
                        verifier_move_ordinal: first_move,
                        intra_move_ordinal: intra + 1,
                        kind: CompactMaskingDisclosureKind::FreshSourceQueries {
                            epoch: role.epoch,
                        },
                        source_rank_increments: Vec::new(),
                        output_coordinate_count: rank,
                        image: coefficient_map_image(
                            coefficient_maps,
                            CompactMaskingViewRole::Mirror,
                            role.epoch,
                            u8::try_from(WHIR_FOLD_COUNT_PER_EPOCH - 1)
                                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
                            0,
                            0,
                        )?,
                    });
                }
                17 => {
                    let epoch = inputs
                        .whir_epochs
                        .iter()
                        .find(|epoch| epoch.epoch == role.epoch)
                        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
                    let group = epoch
                        .external_mask_groups
                        .iter()
                        .chain(&epoch.internal_mask_groups)
                        .nth(usize::from(role.batch_ordinal))
                        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
                    let query = unique_query_set(transcript, query_refs[0].0, query_refs[0].1)?;
                    let rank = structured_reed_solomon_rank(
                        group.message_length,
                        group.randomness_length,
                        group.domain_size,
                        group.width,
                        &query.indices,
                    )?;
                    steps.push(PendingStep {
                        verifier_move_ordinal: first_move,
                        intra_move_ordinal: intra + 1,
                        kind: CompactMaskingDisclosureKind::FreshMaskQueries {
                            epoch: role.epoch,
                            group_ordinal: role.batch_ordinal,
                        },
                        source_rank_increments: Vec::new(),
                        output_coordinate_count: rank,
                        image: coefficient_map_image(
                            coefficient_maps,
                            CompactMaskingViewRole::Mirror,
                            role.epoch,
                            role.batch_ordinal,
                            1,
                            0,
                        )?,
                    });
                }
                _ => return Err(CompactMaskingEntropyError::InvalidContract),
            }
        }
    }
    Ok(())
}

fn append_query_steps_for_move(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    transcript: &CompactMaskingEntropyTranscript,
    move_ordinal: u32,
    steps: &mut Vec<PendingStep>,
) -> Result<(), CompactMaskingEntropyError> {
    append_query_steps_with_move_filter(
        inputs,
        coefficient_maps,
        transcript,
        Some(move_ordinal),
        steps,
    )
}

fn validate_decoded_message(
    move_contract: &CompactVerifierMoveContract,
    message: &DecodedFixedUniformVerifierMessage,
) -> Result<(), CompactMaskingEntropyError> {
    if u64::try_from(message.extension_elements().len()).ok()
        != Some(move_contract.message_geometry.extension_output_count())
        || u64::try_from(message.base_field_elements().len()).ok()
            != Some(move_contract.message_geometry.base_field_output_count())
        || message.distinct_query_groups().len()
            != move_contract.message_geometry.distinct_query_groups().len()
    {
        return Err(CompactMaskingEntropyError::InvalidContract);
    }
    for (indices, geometry) in message
        .distinct_query_groups()
        .iter()
        .zip(move_contract.message_geometry.distinct_query_groups())
    {
        if u64::try_from(indices.len()).ok() != Some(geometry.query_count())
            || indices
                .iter()
                .any(|index| *index >= geometry.domain_cardinality())
            || indices.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(CompactMaskingEntropyError::InvalidQuerySet);
        }
    }
    Ok(())
}

fn append_message_to_transcript(
    transcript: &mut CompactMaskingEntropyTranscript,
    move_contract: &CompactVerifierMoveContract,
    message: &DecodedFixedUniformVerifierMessage,
) -> Result<(), CompactMaskingEntropyError> {
    for role in &move_contract.role_coordinates {
        let extension_start = usize::try_from(role.extension_output_start)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        let extension_end = usize::try_from(role.extension_output_end)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        let challenges = message.extension_elements()[extension_start..extension_end]
            .iter()
            .copied()
            .map(compact_challenge_from_production)
            .collect::<Vec<_>>();
        match role.role_tag {
            3 => {
                let (constraint_combining_challenge, equality_point) = challenges
                    .split_first()
                    .ok_or(CompactMaskingEntropyError::MissingTranscriptInput)?;
                if transcript.cfw_constraint_combining_challenge.is_some()
                    || !transcript.cfw_equality_point.is_empty()
                    || equality_point.is_empty()
                {
                    return Err(CompactMaskingEntropyError::DuplicateTranscriptInput);
                }
                transcript.cfw_constraint_combining_challenge =
                    Some(*constraint_combining_challenge);
                transcript
                    .cfw_equality_point
                    .extend_from_slice(equality_point);
            }
            4 => transcript.cfw_round_challenges.extend(challenges),
            8 => {
                if let Some(record) = transcript.sumcheck_challenges.iter_mut().find(|record| {
                    record.epoch == role.epoch && record.batch_ordinal == role.batch_ordinal
                }) {
                    record.challenges.extend(challenges);
                } else {
                    transcript
                        .sumcheck_challenges
                        .push(CompactMaskingSumcheckChallenges {
                            epoch: role.epoch,
                            batch_ordinal: role.batch_ordinal,
                            challenges,
                        });
                }
            }
            _ => {}
        }
    }
    for (group_ordinal, indices) in message.distinct_query_groups().iter().enumerate() {
        transcript.query_sets.push(CompactMaskingQuerySet {
            logical_verifier_move_ordinal: move_contract.ordinal,
            distinct_query_group_ordinal: u32::try_from(group_ordinal)
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
            indices: indices.clone(),
        });
    }
    Ok(())
}

struct CarriedMaskQueryContext<'operation, 'contract> {
    inputs: &'operation CompactPublicKeyVerifierInputs<'contract>,
    coefficient_maps: &'operation CompactMaskingCoefficientMapCertificate,
    transcript: &'operation CompactMaskingEntropyTranscript,
    move_ordinal_filter: Option<u32>,
}

fn append_carried_mask_query_steps(
    context: CarriedMaskQueryContext<'_, '_>,
    component: &CompactResponseComponentGeometry,
    role: &CompactResponseComponentRoleContract,
    intra: u32,
    steps: &mut Vec<PendingStep>,
) -> Result<(), CompactMaskingEntropyError> {
    let CarriedMaskQueryContext {
        inputs,
        coefficient_maps,
        transcript,
        move_ordinal_filter,
    } = context;
    let (epoch, group_ordinal, contract_role_tag) = mask_group_coordinate(inputs, role)?;
    let refs = component_query_refs(component);
    let map_ordinal = coefficient_maps
        .maps()
        .iter()
        .position(|map| {
            map.coordinate.role == CompactMaskingViewRole::CarriedMask
                && map.coordinate.epoch == epoch.epoch
                && map.coordinate.batch_ordinal == group_ordinal
                && map.coordinate.coordinate == u32::from(contract_role_tag)
        })
        .ok_or(CompactMaskingEntropyError::InvalidCoefficientMap)?;
    let map = &coefficient_maps.maps()[map_ordinal];
    let CompactCoefficientProjection::CarriedMaskReedSolomon {
        lane_count,
        message_length_per_lane,
        randomness_length_per_lane,
        domain_size,
        ..
    } = map.projection
    else {
        return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
    };
    if role.role_tag == 5 {
        if refs.len() != 2 || contract_role_tag != 1 {
            return Err(CompactMaskingEntropyError::InvalidContract);
        }
        let main_map = coefficient_maps
            .maps()
            .iter()
            .find(|candidate| {
                candidate.coordinate.role == CompactMaskingViewRole::CarriedMask
                    && candidate.coordinate.epoch == 2
                    && candidate.coordinate.coordinate == 1
            })
            .ok_or(CompactMaskingEntropyError::InvalidCoefficientMap)?;
        let CompactCoefficientProjection::CarriedMaskReedSolomon {
            lane_count: main_lane_count,
            message_length_per_lane: main_message_length,
            randomness_length_per_lane: main_randomness_length,
            domain_size: main_domain_size,
            ..
        } = main_map.projection
        else {
            return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
        };
        if (
            main_lane_count,
            main_message_length,
            main_randomness_length,
            main_domain_size,
        ) != (
            lane_count,
            message_length_per_lane,
            randomness_length_per_lane,
            domain_size,
        ) {
            return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
        }
        validate_shared_commitment_union_root(coefficient_maps, refs.as_slice())?;
        let first = unique_query_set(transcript, refs[0].0, refs[0].1)?;
        let first_rank = structured_reed_solomon_rank(
            message_length_per_lane,
            randomness_length_per_lane,
            domain_size,
            lane_count,
            &first.indices,
        )?;
        let first_output_count = checked_product(&[
            lane_count,
            u64::try_from(first.indices.len())
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
        ])?;
        if move_ordinal_filter.is_none() || move_ordinal_filter == Some(refs[0].0) {
            steps.push(pending_with_image(
                refs[0].0,
                intra,
                CompactMaskingDisclosureKind::CarriedMaskQueries {
                    epoch: 1,
                    group_ordinal: 0,
                    contract_role_tag,
                },
                PrivateSource::CrossEpochEncoding,
                first_output_count,
                first_rank,
                CompactMaskingDisclosureImage::CoefficientMapImage {
                    map_ordinal,
                    first_output_coordinate: 0,
                },
            ));
        }
        if move_ordinal_filter.is_some() && move_ordinal_filter != Some(refs[1].0) {
            return Ok(());
        }
        let second = unique_query_set(transcript, refs[1].0, refs[1].1)?;
        let mut union = first.indices.clone();
        union.extend_from_slice(&second.indices);
        union.sort_unstable();
        union.dedup();
        let union_rank = structured_reed_solomon_rank(
            message_length_per_lane,
            randomness_length_per_lane,
            domain_size,
            lane_count,
            &union,
        )?;
        let second_output_count = checked_product(&[
            lane_count,
            u64::try_from(second.indices.len())
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
        ])?;
        steps.push(pending_with_image(
            refs[1].0,
            intra,
            CompactMaskingDisclosureKind::CarriedMaskQueries {
                epoch: 2,
                group_ordinal: main_map.coordinate.batch_ordinal,
                contract_role_tag,
            },
            PrivateSource::CrossEpochEncoding,
            second_output_count,
            union_rank
                .checked_sub(first_rank)
                .ok_or(CompactMaskingEntropyError::RankFailure)?,
            CompactMaskingDisclosureImage::CoefficientMapImage {
                map_ordinal,
                first_output_coordinate: first_output_count,
            },
        ));
        return Ok(());
    }
    let query = unique_query_set(transcript, refs[0].0, refs[0].1)?;
    let query_rank = structured_reed_solomon_rank(
        message_length_per_lane,
        randomness_length_per_lane,
        domain_size,
        lane_count,
        &query.indices,
    )?;
    let source = match contract_role_tag {
        2 => PrivateSource::CfwInnerEncoding,
        3 => PrivateSource::CfwOuterEncoding,
        _ => PrivateSource::WhirMaskEncoding {
            epoch: epoch.epoch,
            group_ordinal,
        },
    };
    let output_coordinate_count = checked_product(&[
        lane_count,
        u64::try_from(query.indices.len())
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
    ])?;
    steps.push(pending_with_image(
        refs[0].0,
        intra,
        CompactMaskingDisclosureKind::CarriedMaskQueries {
            epoch: epoch.epoch,
            group_ordinal,
            contract_role_tag,
        },
        source,
        output_coordinate_count,
        query_rank,
        CompactMaskingDisclosureImage::CoefficientMapImage {
            map_ordinal,
            first_output_coordinate: 0,
        },
    ));
    Ok(())
}

#[cfg(test)]
fn append_base_reveal_steps(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    transcript: &CompactMaskingEntropyTranscript,
    steps: &mut Vec<PendingStep>,
) -> Result<(), CompactMaskingEntropyError> {
    for epoch in inputs.whir_epochs {
        append_base_reveal_steps_for_epoch(inputs, transcript, epoch.epoch, steps)?;
    }
    Ok(())
}

fn append_base_reveal_steps_for_epoch(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    transcript: &CompactMaskingEntropyTranscript,
    epoch_tag: u8,
    steps: &mut Vec<PendingStep>,
) -> Result<(), CompactMaskingEntropyError> {
    let epoch = inputs
        .whir_epochs
        .iter()
        .find(|epoch| epoch.epoch == epoch_tag)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    let reveal_move = inputs
        .verifier_moves
        .iter()
        .find(|move_| {
            move_
                .role_coordinates
                .iter()
                .any(|role| role.role_tag == 11 && role.epoch == epoch.epoch)
        })
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    let claim = unique_base_claim(transcript, epoch.epoch)?;
    let (claim_source, claim_pivot) = claim_pivot_location(inputs, claim)?
        .ok_or(CompactMaskingEntropyError::InvalidCoefficientVector)?;
    let folds = epoch_folds(inputs, epoch.epoch)?;
    let final_fold = folds
        .last()
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    let response_index = usize::try_from(reveal_move.ordinal)
        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    let geometry = inputs
        .response_merkle_geometries
        .get(response_index)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    let roles = inputs
        .response_component_roles
        .get(response_index)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    if geometry.components().len() != roles.len() {
        return Err(CompactMaskingEntropyError::InvalidContract);
    }
    // This response is committed before the role-11 message supplies the
    // final query coordinates. Its scalar disclosures therefore precede
    // the query openings from that message.
    for (component_index, (component, role)) in geometry.components().iter().zip(roles).enumerate()
    {
        if role.epoch != epoch.epoch || !(19..=21).contains(&role.role_tag) {
            continue;
        }
        let intra_move_ordinal = u32::try_from(component_index)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        let (kind, output_coordinate_count, source_rank_increments, image) = match role.role_tag {
            19 => {
                let source = PrivateSource::WhirFreshSourceMessage { epoch: epoch.epoch };
                let dimension = final_fold.message_length;
                (
                    CompactMaskingDisclosureKind::BaseBlindedSourceMessage { epoch: epoch.epoch },
                    dimension,
                    vec![(
                        source,
                        remaining_identity_rank(dimension, source, Some(claim_source))?,
                    )],
                    identity_reveal_image(source, claim_source, claim_pivot),
                )
            }
            20 => {
                let source = PrivateSource::WhirFreshSourceEncoding { epoch: epoch.epoch };
                let dimension = final_fold.hiding_randomness_length;
                (
                    CompactMaskingDisclosureKind::BaseBlindedSourceRandomness {
                        epoch: epoch.epoch,
                    },
                    dimension,
                    vec![(source, dimension)],
                    CompactMaskingDisclosureImage::FullCoordinateSpace,
                )
            }
            21 => {
                let group_ordinal = role.batch_ordinal;
                let group = epoch
                    .external_mask_groups
                    .iter()
                    .chain(&epoch.internal_mask_groups)
                    .nth(usize::from(group_ordinal))
                    .ok_or(CompactMaskingEntropyError::InvalidContract)?;
                let message_source = PrivateSource::WhirFreshMaskMessage {
                    epoch: epoch.epoch,
                    group_ordinal,
                };
                let encoding_source = PrivateSource::WhirFreshMaskEncoding {
                    epoch: epoch.epoch,
                    group_ordinal,
                };
                let message_dimension = checked_product(&[group.width, group.message_length])?;
                let encoding_dimension = checked_product(&[group.width, group.randomness_length])?;
                (
                    CompactMaskingDisclosureKind::BaseBlindedMaskGroup {
                        epoch: epoch.epoch,
                        group_ordinal,
                    },
                    checked_add(message_dimension, encoding_dimension)?,
                    vec![
                        (
                            message_source,
                            remaining_identity_rank(
                                message_dimension,
                                message_source,
                                Some(claim_source),
                            )?,
                        ),
                        (encoding_source, encoding_dimension),
                    ],
                    identity_reveal_image(message_source, claim_source, claim_pivot),
                )
            }
            _ => unreachable!(),
        };
        require_component(component, output_coordinate_count, 1)?;
        steps.push(PendingStep {
            verifier_move_ordinal: reveal_move.ordinal,
            intra_move_ordinal,
            kind,
            source_rank_increments,
            output_coordinate_count,
            image,
        });
    }
    Ok(())
}

fn validate_shared_commitment_union_root(
    certificate: &CompactMaskingCoefficientMapCertificate,
    query_refs: &[(u32, u32)],
) -> Result<(), CompactMaskingEntropyError> {
    let [owned_pre_challenge_ref, reused_main_ref] = query_refs else {
        return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
    };
    let mut shared_roots = certificate
        .construction_commitment_embeddings()
        .iter()
        .filter(|embedding| {
            matches!(
                embedding.ownership,
                CompactConstructionCommitmentOwnership::OwnedByPreChallengeEpochReusedByMainEpoch
            )
        });
    let Some(shared_root) = shared_roots.next() else {
        return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
    };
    if shared_roots.next().is_some()
        || shared_root.component_role.role_tag != 5
        || !matches!(
            shared_root.query_source,
            CompactCommitmentQuerySource::SharedCrossEpochUnion {
                owned_pre_challenge,
                reused_main,
            } if *owned_pre_challenge_ref
                == (
                    owned_pre_challenge.logical_verifier_move_ordinal,
                    owned_pre_challenge.distinct_query_group_ordinal,
                )
                && *reused_main_ref
                    == (
                        reused_main.logical_verifier_move_ordinal,
                        reused_main.distinct_query_group_ordinal,
                    )
        )
    {
        return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
    }
    Ok(())
}

fn remaining_identity_rank(
    dimension: u64,
    source: PrivateSource,
    claim_source: Option<PrivateSource>,
) -> Result<u64, CompactMaskingEntropyError> {
    dimension
        .checked_sub(u64::from(claim_source == Some(source)))
        .ok_or(CompactMaskingEntropyError::RankFailure)
}

fn claim_pivot_location(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    claim: &CompactBaseFreshClaimCoefficients,
) -> Result<Option<(PrivateSource, u64)>, CompactMaskingEntropyError> {
    let epoch = inputs
        .whir_epochs
        .iter()
        .find(|epoch| epoch.epoch == claim.epoch)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    let folds = epoch_folds(inputs, claim.epoch)?;
    let source_message_count = usize::try_from(
        folds
            .last()
            .ok_or(CompactMaskingEntropyError::InvalidContract)?
            .message_length,
    )
    .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    let mut pivot = claim.coefficients[..source_message_count]
        .iter()
        .rposition(|coefficient| *coefficient != CompactChallengeField::ZERO)
        .map(|coordinate| {
            u64::try_from(coordinate)
                .map(|coordinate| {
                    (
                        PrivateSource::WhirFreshSourceMessage { epoch: claim.epoch },
                        coordinate,
                    )
                })
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)
        })
        .transpose()?;
    let mut offset = source_message_count;
    for (group_index, group) in epoch
        .external_mask_groups
        .iter()
        .chain(&epoch.internal_mask_groups)
        .enumerate()
    {
        let count = usize::try_from(checked_product(&[group.width, group.message_length])?)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        let end = offset
            .checked_add(count)
            .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
        if let Some(message_coordinate) = claim.coefficients[offset..end]
            .iter()
            .rposition(|coefficient| *coefficient != CompactChallengeField::ZERO)
        {
            let message_coordinate = u64::try_from(message_coordinate)
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
            let lane = message_coordinate / group.message_length;
            let coordinate_in_lane = message_coordinate % group.message_length;
            let output_coordinate = checked_add(
                checked_product(&[
                    lane,
                    checked_add(group.message_length, group.randomness_length)?,
                ])?,
                coordinate_in_lane,
            )?;
            pivot = Some((
                PrivateSource::WhirFreshMaskMessage {
                    epoch: claim.epoch,
                    group_ordinal: u8::try_from(group_index)
                        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
                },
                output_coordinate,
            ));
        }
        offset = end;
    }
    if offset != claim.coefficients.len() {
        return Err(CompactMaskingEntropyError::InvalidCoefficientVector);
    }
    Ok(pivot)
}

fn claim_pivot_source(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    claim: &CompactBaseFreshClaimCoefficients,
) -> Result<Option<PrivateSource>, CompactMaskingEntropyError> {
    Ok(claim_pivot_location(inputs, claim)?.map(|(source, _)| source))
}

fn identity_reveal_image(
    source: PrivateSource,
    claim_source: PrivateSource,
    claim_pivot: u64,
) -> CompactMaskingDisclosureImage {
    if source == claim_source {
        CompactMaskingDisclosureImage::LinearClaimFiber {
            pivot_output_coordinate: claim_pivot,
        }
    } else {
        CompactMaskingDisclosureImage::FullCoordinateSpace
    }
}

fn cfw_outer_incremental_ranks(
    certificate: &CompactMaskingCoefficientMapCertificate,
    challenges: &[CompactChallengeField],
) -> Result<Vec<u64>, CompactMaskingEntropyError> {
    let map = certificate
        .maps()
        .iter()
        .find(|map| {
            map.coordinate.role == CompactMaskingViewRole::Sumcheck
                && map.coordinate.epoch == 0
                && map.coordinate.coordinate == 1
        })
        .ok_or(CompactMaskingEntropyError::InvalidCoefficientMap)?;
    if !matches!(
        map.projection,
        CompactCoefficientProjection::CfwOuterTranscript { round_count }
            if usize::try_from(round_count).ok() == Some(challenges.len())
    ) {
        return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
    }
    let columns = challenges
        .len()
        .checked_mul(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
        .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
    let mut row_groups = vec![Vec::new(); challenges.len() + 2];
    for column in 0..columns {
        let mut masks = vec![
            [CompactChallengeField::ZERO; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH];
            challenges.len()
        ];
        masks[column / COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]
            [column % COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH] = CompactChallengeField::ONE;
        let view = apply_cfw_outer_mask_view(&masks, challenges)
            .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientMap)?;
        row_groups[0].push(view.auxiliary_target);
        for (round, polynomial) in view.round_polynomials.into_iter().enumerate() {
            for (coefficient, value) in polynomial.into_iter().enumerate() {
                let row = 1 + round;
                if row_groups[row].len() < (coefficient + 1) * columns {
                    row_groups[row]
                        .resize((coefficient + 1) * columns, CompactChallengeField::ZERO);
                }
                row_groups[row][coefficient * columns + column] = value;
            }
        }
        for (evaluation, value) in view.outer_evaluations.into_iter().enumerate() {
            let row = challenges.len() + 1;
            if row_groups[row].len() < (evaluation + 1) * columns {
                row_groups[row].resize((evaluation + 1) * columns, CompactChallengeField::ZERO);
            }
            row_groups[row][evaluation * columns + column] = value;
        }
    }
    incremental_group_ranks(row_groups, columns)
}

fn certified_cfw_round_conditional_rank(
    certificate: &CompactMaskingCoefficientMapCertificate,
    expected_round_count: u64,
) -> Result<u64, CompactMaskingEntropyError> {
    let map = certificate
        .maps()
        .iter()
        .find(|map| {
            map.coordinate.role == CompactMaskingViewRole::Sumcheck
                && map.coordinate.epoch == 0
                && map.coordinate.batch_ordinal == 0
                && map.coordinate.coordinate == 1
        })
        .ok_or(CompactMaskingEntropyError::InvalidCoefficientMap)?;
    if !matches!(
        (&map.projection, map.surjectivity),
        (
            CompactCoefficientProjection::CfwOuterTranscript { round_count },
            CompactSurjectivityWitness::CfwOuterFullColumnRank {
                round_count: witness_round_count,
            },
        ) if *round_count == expected_round_count
            && witness_round_count == expected_round_count
    ) || map.private_coordinate_count
        != checked_product(&[expected_round_count, CFW_OUTER_MASK_MESSAGE_LENGTH_U64])?
    {
        return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
    }

    // The compiler witness assigns one pivot to every nonconstant
    // coefficient of the eight-coordinate CFW round polynomial. The remaining
    // coordinate is fixed by the preceding sumcheck claim, so every live round
    // has a seven-dimensional conditional image.
    CFW_OUTER_MASK_MESSAGE_LENGTH_U64
        .checked_sub(1)
        .ok_or(CompactMaskingEntropyError::RankFailure)
}

#[cfg(test)]
fn cfw_inner_terminal_rank(
    certificate: &CompactMaskingCoefficientMapCertificate,
    challenges: &[CompactChallengeField],
) -> Result<u64, CompactMaskingEntropyError> {
    let map = certificate
        .maps()
        .iter()
        .find(|map| {
            map.coordinate.role == CompactMaskingViewRole::Terminal
                && map.coordinate.epoch == 0
                && map.coordinate.coordinate == 1
        })
        .ok_or(CompactMaskingEntropyError::InvalidCoefficientMap)?;
    let columns = usize::try_from(map.private_coordinate_count)
        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    let mut rows = vec![vec![CompactChallengeField::ZERO; columns]; COMPACT_CFW_MATRIX_COUNT];
    for column in 0..columns {
        let mut coefficients = vec![[CompactChallengeField::ZERO; 2]; columns / 2];
        coefficients[column / 2][column % 2] = CompactChallengeField::ONE;
        let view = apply_cfw_inner_terminal_view(&coefficients, challenges)
            .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientMap)?;
        for (row, value) in rows.iter_mut().zip(view) {
            row[column] = value;
        }
    }
    let rank = matrix_rank(&rows)?;
    if rank != COMPACT_CFW_MATRIX_COUNT {
        return Err(CompactMaskingEntropyError::RankFailure);
    }
    u64::try_from(rank).map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)
}

#[cfg(test)]
fn cross_epoch_rank(
    certificate: &CompactMaskingCoefficientMapCertificate,
    inputs: &CompactPublicKeyVerifierInputs<'_>,
) -> Result<u64, CompactMaskingEntropyError> {
    let map = certificate
        .maps()
        .iter()
        .find(|map| map.coordinate.role == CompactMaskingViewRole::ExplicitPoint)
        .ok_or(CompactMaskingEntropyError::InvalidCoefficientMap)?;
    let cross_epoch = inputs.cfw_configuration.cross_epoch();
    validated_cross_epoch_rank(
        map,
        cross_epoch.copied_element_count,
        cross_epoch.point_coordinate_count,
    )
}

#[cfg(test)]
fn validated_cross_epoch_rank(
    map: &CompactCoefficientToViewMap,
    copied_element_count: u64,
    point_coordinate_count: u32,
) -> Result<u64, CompactMaskingEntropyError> {
    let expected_private_coordinate_count = copied_element_count
        .checked_add(2)
        .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
    let CompactCoefficientProjection::CrossEpochExplicitPoint {
        copied_element_count: map_copied_element_count,
        point_coordinate_count: map_point_coordinate_count,
    } = &map.projection
    else {
        return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
    };
    if *map_copied_element_count != copied_element_count
        || *map_point_coordinate_count != point_coordinate_count
        || map.private_coordinate_count != expected_private_coordinate_count
        || map.view_coordinate_count != 3
        || map.surjectivity != CompactSurjectivityWitness::CrossEpochTwoMaskCorrection
    {
        return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
    }

    // Conditional on the copied-source evaluation `e`, the two masks map to
    // `[e + pre, e + main, pre - main]`. Their coefficient columns
    // `[1, 0, 1]` and `[0, 1, -1]` are independent, so the conditional image
    // has rank two exactly as certified by the load-bearing witness above.
    Ok(2)
}

#[cfg(test)]
fn sumcheck_incremental_ranks(
    certificate: &CompactMaskingCoefficientMapCertificate,
    role: &CompactResponseComponentRoleContract,
    challenges: &[CompactChallengeField],
) -> Result<Vec<u64>, CompactMaskingEntropyError> {
    let map = certificate
        .maps()
        .iter()
        .find(|map| {
            map.coordinate.role == CompactMaskingViewRole::Sumcheck
                && map.coordinate.epoch == role.epoch
                && map.coordinate.batch_ordinal == role.batch_ordinal
                && map.coordinate.coordinate == 0
        })
        .ok_or(CompactMaskingEntropyError::InvalidCoefficientMap)?;
    let columns = usize::try_from(map.private_coordinate_count)
        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    let rounds = challenges.len();
    if columns != rounds * 3 {
        return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
    }
    let mut groups = vec![Vec::new(); rounds + 1];
    for column in 0..columns {
        let mut masks = vec![vec![CompactChallengeField::ZERO; 3]; rounds];
        masks[column / 3][column % 3] = CompactChallengeField::ONE;
        let view = apply_whir_sumcheck_mask_view(&masks, challenges)
            .map_err(|_| CompactMaskingEntropyError::InvalidCoefficientMap)?;
        groups[0].push(view[0]);
        for round in 0..rounds {
            for coordinate in 0..2 {
                if groups[round + 1].len() < (coordinate + 1) * columns {
                    groups[round + 1]
                        .resize((coordinate + 1) * columns, CompactChallengeField::ZERO);
                }
                groups[round + 1][coordinate * columns + column] = view[1 + round * 2 + coordinate];
            }
        }
    }
    let increments = incremental_group_ranks(groups, columns)?;
    if increments.first() != Some(&1) || increments[1..].iter().any(|rank| *rank != 2) {
        return Err(CompactMaskingEntropyError::RankFailure);
    }
    Ok(increments)
}

fn incremental_group_ranks(
    flattened_groups: Vec<Vec<CompactChallengeField>>,
    column_count: usize,
) -> Result<Vec<u64>, CompactMaskingEntropyError> {
    let mut rows = Vec::new();
    let mut preceding_rank = 0_usize;
    let mut increments = Vec::with_capacity(flattened_groups.len());
    for group in flattened_groups {
        if group.len() % column_count != 0 {
            return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
        }
        rows.extend(group.chunks_exact(column_count).map(<[_]>::to_vec));
        let rank = matrix_rank(&rows)?;
        increments.push(
            u64::try_from(rank - preceding_rank)
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
        );
        preceding_rank = rank;
    }
    Ok(increments)
}

fn structured_reed_solomon_rank(
    message_length: u64,
    randomness_length: u64,
    domain_size: u64,
    lane_count: u64,
    indices: &[u64],
) -> Result<u64, CompactMaskingEntropyError> {
    if !domain_size.is_power_of_two()
        || randomness_length == 0
        || indices.is_empty()
        || u64::try_from(indices.len())
            .ok()
            .is_none_or(|count| count > randomness_length)
        || indices.iter().any(|position| *position >= domain_size)
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(CompactMaskingEntropyError::InvalidQuerySet);
    }
    let log_domain_size = usize::try_from(domain_size.ilog2())
        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    let generator = CompactChallengeField::from(Goldilocks::two_adic_generator(log_domain_size));
    let points = indices
        .iter()
        .map(|position| generator.exp_u64(*position))
        .collect::<Vec<_>>();
    if points.contains(&CompactChallengeField::ZERO)
        || points
            .iter()
            .enumerate()
            .any(|(index, point)| points[..index].contains(point))
    {
        return Err(CompactMaskingEntropyError::RankFailure);
    }
    // Check the actual first randomness-suffix column is nonzero at every
    // sampled point. Together with pairwise-distinct points, this is the
    // generalized-Vandermonde pivot certificate for all requested rows.
    if indices.iter().any(|position| {
        reed_solomon_query_coefficient(generator, *position, message_length)
            == CompactChallengeField::ZERO
    }) {
        return Err(CompactMaskingEntropyError::RankFailure);
    }
    checked_product(&[
        lane_count,
        u64::try_from(indices.len()).map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
    ])
}

fn matrix_rank(rows: &[Vec<CompactChallengeField>]) -> Result<usize, CompactMaskingEntropyError> {
    if rows.is_empty() {
        return Ok(0);
    }
    let column_count = rows[0].len();
    if column_count == 0 || rows.iter().any(|row| row.len() != column_count) {
        return Err(CompactMaskingEntropyError::InvalidCoefficientMap);
    }
    let mut matrix = rows.to_vec();
    let mut rank = 0_usize;
    for column in 0..column_count {
        let Some(offset) = matrix[rank..]
            .iter()
            .position(|row| row[column] != CompactChallengeField::ZERO)
        else {
            continue;
        };
        matrix.swap(rank, rank + offset);
        let inverse = matrix[rank][column].inverse();
        for value in &mut matrix[rank][column..] {
            *value *= inverse;
        }
        let pivot = matrix[rank][column..].to_vec();
        for row in matrix.iter_mut().skip(rank + 1) {
            let factor = row[column];
            for (value, pivot_value) in row[column..].iter_mut().zip(&pivot) {
                *value -= factor * *pivot_value;
            }
        }
        rank += 1;
        if rank == matrix.len() {
            break;
        }
    }
    Ok(rank)
}

fn unique_query_set(
    transcript: &CompactMaskingEntropyTranscript,
    move_ordinal: u32,
    group_ordinal: u32,
) -> Result<&CompactMaskingQuerySet, CompactMaskingEntropyError> {
    let mut matches = transcript.query_sets.iter().filter(|query| {
        query.logical_verifier_move_ordinal == move_ordinal
            && query.distinct_query_group_ordinal == group_ordinal
    });
    let value = matches
        .next()
        .ok_or(CompactMaskingEntropyError::MissingTranscriptInput)?;
    if matches.next().is_some() {
        return Err(CompactMaskingEntropyError::DuplicateTranscriptInput);
    }
    Ok(value)
}

struct CompactStepQueryPositions<'transcript> {
    preceding: &'transcript [u64],
    current: &'transcript [u64],
}

fn query_component_for_disclosure<'contract>(
    inputs: &'contract CompactPublicKeyVerifierInputs<'_>,
    disclosure_kind: CompactMaskingDisclosureKind,
) -> Result<
    (
        &'contract CompactResponseMerkleGeometry,
        &'contract CompactResponseComponentGeometry,
    ),
    CompactMaskingEntropyError,
> {
    let mut matches = inputs
        .response_merkle_geometries
        .iter()
        .zip(inputs.response_component_roles)
        .flat_map(|(geometry, roles)| {
            geometry
                .components()
                .iter()
                .zip(roles)
                .map(move |(component, role)| (geometry, component, role))
        })
        .filter(|(_, _, role)| match disclosure_kind {
            CompactMaskingDisclosureKind::SourceQueries {
                epoch,
                source_ordinal,
            } => source_coordinate_for_role(role).ok() == Some((epoch, source_ordinal)),
            CompactMaskingDisclosureKind::CarriedMaskQueries {
                epoch,
                group_ordinal,
                contract_role_tag,
            } => {
                if role.role_tag == 5 && contract_role_tag == 1 {
                    mask_group_ordinal_for_contract_coordinate(inputs, epoch, contract_role_tag, 0)
                        .is_ok_and(|role_group| role_group == group_ordinal)
                } else {
                    mask_group_coordinate(inputs, role).is_ok_and(
                        |(role_epoch, role_group, role_contract_tag)| {
                            role_epoch.epoch == epoch
                                && role_group == group_ordinal
                                && role_contract_tag == contract_role_tag
                        },
                    )
                }
            }
            CompactMaskingDisclosureKind::FreshSourceQueries { epoch } => {
                role.epoch == epoch && role.role_tag == 16
            }
            CompactMaskingDisclosureKind::FreshMaskQueries {
                epoch,
                group_ordinal,
            } => role.epoch == epoch && role.role_tag == 17 && role.batch_ordinal == group_ordinal,
            _ => false,
        });
    let (geometry, component, _) = matches
        .next()
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    if matches.next().is_some() {
        return Err(CompactMaskingEntropyError::InvalidContract);
    }
    Ok((geometry, component))
}

fn query_positions_for_disclosure<'transcript>(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    transcript: &'transcript CompactMaskingEntropyTranscript,
    disclosure_kind: CompactMaskingDisclosureKind,
) -> Result<CompactStepQueryPositions<'transcript>, CompactMaskingEntropyError> {
    let (_, component) = query_component_for_disclosure(inputs, disclosure_kind)?;
    let references = component_query_refs(component);
    let reference_index = match disclosure_kind {
        CompactMaskingDisclosureKind::CarriedMaskQueries { epoch: 2, .. }
            if references.len() == 2 =>
        {
            1
        }
        _ => 0,
    };
    let (move_ordinal, query_group_ordinal) = *references
        .get(reference_index)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    let current: &[u64] = unique_query_set(transcript, move_ordinal, query_group_ordinal)?
        .indices
        .as_slice();
    let preceding: &[u64] = if reference_index == 1 {
        let (preceding_move, preceding_group) = references[0];
        unique_query_set(transcript, preceding_move, preceding_group)?
            .indices
            .as_slice()
    } else {
        &[]
    };
    Ok(CompactStepQueryPositions { preceding, current })
}

fn sumcheck_challenges_for_prefix(
    transcript: &CompactMaskingEntropyTranscript,
    epoch: u8,
    batch_ordinal: u8,
) -> Result<&[CompactChallengeField], CompactMaskingEntropyError> {
    Ok(transcript
        .sumcheck_challenges
        .iter()
        .find(|record| record.epoch == epoch && record.batch_ordinal == batch_ordinal)
        .map_or(&[], |record| record.challenges.as_slice()))
}

#[cfg(test)]
fn linear_claim_output_covector(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    transcript: &CompactMaskingEntropyTranscript,
    step: &CompactMaskingEntropyStep,
) -> Result<Vec<CompactChallengeField>, CompactMaskingEntropyError> {
    let (epoch_tag, group_ordinal, source_randomness) = match step.kind {
        CompactMaskingDisclosureKind::BaseBlindedSourceMessage { epoch } => (epoch, None, false),
        CompactMaskingDisclosureKind::BaseBlindedSourceRandomness { epoch } => (epoch, None, true),
        CompactMaskingDisclosureKind::BaseBlindedMaskGroup {
            epoch,
            group_ordinal,
        } => (epoch, Some(group_ordinal), false),
        _ => return Err(CompactMaskingEntropyError::InvalidCoefficientVector),
    };
    let claim = unique_base_claim(transcript, epoch_tag)?;
    let epoch = inputs
        .whir_epochs
        .iter()
        .find(|epoch| epoch.epoch == epoch_tag)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    let final_fold = epoch_folds(inputs, epoch_tag)?
        .last()
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    if source_randomness {
        return Ok(vec![
            CompactChallengeField::ZERO;
            usize::try_from(final_fold.hiding_randomness_length)
                .map_err(|_| {
                    CompactMaskingEntropyError::ArithmeticOverflow
                })?
        ]);
    }
    let source_message_count = final_fold.message_length;
    let source_end = usize::try_from(source_message_count)
        .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    if group_ordinal.is_none() {
        return Ok(claim.coefficients[..source_end].to_vec());
    }
    let selected_group = usize::from(group_ordinal.unwrap_or_default());
    let mut claim_offset = source_end;
    for (group_index, group) in epoch
        .external_mask_groups
        .iter()
        .chain(&epoch.internal_mask_groups)
        .enumerate()
    {
        let message_count = usize::try_from(checked_product(&[group.width, group.message_length])?)
            .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
        let claim_end = claim_offset
            .checked_add(message_count)
            .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
        if group_index == selected_group {
            let lane_count = usize::try_from(group.width)
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
            let message_length = usize::try_from(group.message_length)
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
            let randomness_length = usize::try_from(group.randomness_length)
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
            let mut output = Vec::with_capacity(
                lane_count
                    .checked_mul(message_length + randomness_length)
                    .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?,
            );
            for lane in 0..lane_count {
                let start = claim_offset + lane * message_length;
                output.extend_from_slice(&claim.coefficients[start..start + message_length]);
                output.resize(
                    output.len() + randomness_length,
                    CompactChallengeField::ZERO,
                );
            }
            return Ok(output);
        }
        claim_offset = claim_end;
    }
    Err(CompactMaskingEntropyError::InvalidCoefficientVector)
}

#[cfg(test)]
fn unique_sumcheck_challenges(
    transcript: &CompactMaskingEntropyTranscript,
    epoch: u8,
    batch_ordinal: u8,
) -> Result<&[CompactChallengeField], CompactMaskingEntropyError> {
    let mut matches = transcript
        .sumcheck_challenges
        .iter()
        .filter(|record| record.epoch == epoch && record.batch_ordinal == batch_ordinal);
    let value = matches
        .next()
        .ok_or(CompactMaskingEntropyError::MissingTranscriptInput)?;
    if matches.next().is_some() {
        return Err(CompactMaskingEntropyError::DuplicateTranscriptInput);
    }
    Ok(&value.challenges)
}

fn unique_base_claim(
    transcript: &CompactMaskingEntropyTranscript,
    epoch: u8,
) -> Result<&CompactBaseFreshClaimCoefficients, CompactMaskingEntropyError> {
    let mut matches = transcript
        .base_fresh_claims
        .iter()
        .filter(|record| record.epoch == epoch);
    let value = matches
        .next()
        .ok_or(CompactMaskingEntropyError::MissingTranscriptInput)?;
    if matches.next().is_some() {
        return Err(CompactMaskingEntropyError::DuplicateTranscriptInput);
    }
    Ok(value)
}

fn component_query_refs(component: &CompactResponseComponentGeometry) -> Vec<(u32, u32)> {
    match component.query_selection() {
        CompactResponseQuerySelection::VerifierMessageDistinctGroup {
            logical_verifier_move_ordinal,
            distinct_query_group_ordinal,
        } => vec![(logical_verifier_move_ordinal, distinct_query_group_ordinal)],
        CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
            first_logical_verifier_move_ordinal,
            first_distinct_query_group_ordinal,
            second_logical_verifier_move_ordinal,
            second_distinct_query_group_ordinal,
        } => vec![
            (
                first_logical_verifier_move_ordinal,
                first_distinct_query_group_ordinal,
            ),
            (
                second_logical_verifier_move_ordinal,
                second_distinct_query_group_ordinal,
            ),
        ],
        _ => Vec::new(),
    }
}

fn mask_group_coordinate<'a>(
    inputs: &'a CompactPublicKeyVerifierInputs<'_>,
    role: &CompactResponseComponentRoleContract,
) -> Result<(&'a CompactWhirEpochContract, u8, u8), CompactMaskingEntropyError> {
    let (epoch_tag, contract_role_tag, coordinate) = match role.role_tag {
        2 => (2, 2, 0),
        4 => (2, 3, 0),
        5 => (1, 1, 0),
        11 => (role.epoch, 4, role.batch_ordinal),
        15 => (role.epoch, 5, role.round_ordinal as u8),
        _ => return Err(CompactMaskingEntropyError::InvalidContract),
    };
    let epoch = inputs
        .whir_epochs
        .iter()
        .find(|epoch| epoch.epoch == epoch_tag)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    let group_ordinal = mask_group_ordinal_for_contract_coordinate(
        inputs,
        epoch_tag,
        contract_role_tag,
        coordinate,
    )?;
    Ok((epoch, group_ordinal, contract_role_tag))
}

fn mask_group_ordinal_for_contract_coordinate(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    epoch_tag: u8,
    contract_role_tag: u8,
    coordinate: u8,
) -> Result<u8, CompactMaskingEntropyError> {
    let epoch = inputs
        .whir_epochs
        .iter()
        .find(|epoch| epoch.epoch == epoch_tag)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    let group_ordinal = epoch
        .external_mask_groups
        .iter()
        .chain(&epoch.internal_mask_groups)
        .position(|group| group.role_tag == contract_role_tag && group.coordinate == coordinate)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    u8::try_from(group_ordinal).map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)
}

fn source_coordinate_for_role(
    role: &CompactResponseComponentRoleContract,
) -> Result<(u8, u8), CompactMaskingEntropyError> {
    match role.role_tag {
        1 => Ok((1, 0)),
        3 => Ok((2, 0)),
        14 if (1..=2).contains(&role.epoch) => Ok((
            role.epoch,
            u8::try_from(role.round_ordinal + 1)
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
        )),
        _ => Err(CompactMaskingEntropyError::InvalidContract),
    }
}

#[cfg(test)]
fn shared_cross_query_overlap(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    transcript: &CompactMaskingEntropyTranscript,
) -> Result<u64, CompactMaskingEntropyError> {
    let component = inputs
        .response_merkle_geometries
        .iter()
        .zip(inputs.response_component_roles)
        .flat_map(|(geometry, roles)| geometry.components().iter().zip(roles))
        .find(|(_, role)| role.role_tag == 5)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?
        .0;
    let refs = component_query_refs(component);
    if refs.len() != 2 {
        return Err(CompactMaskingEntropyError::InvalidContract);
    }
    let first = unique_query_set(transcript, refs[0].0, refs[0].1)?;
    let second = unique_query_set(transcript, refs[1].0, refs[1].1)?;
    u64::try_from(
        second
            .indices
            .iter()
            .filter(|index| first.indices.binary_search(index).is_ok())
            .count(),
    )
    .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)
}

fn epoch_folds<'a>(
    inputs: &'a CompactPublicKeyVerifierInputs<'_>,
    epoch: u8,
) -> Result<&'a [CompactWhirFoldContract], CompactMaskingEntropyError> {
    let first = usize::from(
        epoch
            .checked_sub(1)
            .ok_or(CompactMaskingEntropyError::InvalidContract)?,
    )
    .checked_mul(WHIR_FOLD_COUNT_PER_EPOCH)
    .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
    let folds = inputs
        .whir_folds
        .get(first..first + WHIR_FOLD_COUNT_PER_EPOCH)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?;
    if folds.iter().any(|fold| fold.epoch != epoch) {
        return Err(CompactMaskingEntropyError::InvalidContract);
    }
    Ok(folds)
}

fn base_fresh_message_dimension(
    epoch: &CompactWhirEpochContract,
) -> Result<u64, CompactMaskingEntropyError> {
    let source = 1_u64
        .checked_shl(epoch.final_variable_count)
        .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)?;
    epoch
        .external_mask_groups
        .iter()
        .chain(&epoch.internal_mask_groups)
        .try_fold(source, |sum, group| {
            checked_add(sum, checked_product(&[group.width, group.message_length])?)
        })
}

fn source(source: PrivateSource, dimension: u64) -> SourceState {
    SourceState {
        source,
        dimension,
        rank: 0,
    }
}

fn pending_with_image(
    verifier_move_ordinal: u32,
    intra_move_ordinal: u32,
    kind: CompactMaskingDisclosureKind,
    source: PrivateSource,
    output_coordinate_count: u64,
    source_rank_increment: u64,
    image: CompactMaskingDisclosureImage,
) -> PendingStep {
    PendingStep {
        verifier_move_ordinal,
        intra_move_ordinal,
        kind,
        source_rank_increments: vec![(source, source_rank_increment)],
        output_coordinate_count,
        image,
    }
}

fn pending_step_conditional_rank(step: &PendingStep) -> Result<u64, CompactMaskingEntropyError> {
    let mut seen = Vec::with_capacity(step.source_rank_increments.len());
    let mut rank = 0_u64;
    for (source, increment) in &step.source_rank_increments {
        if seen.contains(source) {
            return Err(CompactMaskingEntropyError::RankFailure);
        }
        seen.push(*source);
        rank = checked_add(rank, *increment)?;
    }
    Ok(rank)
}

fn require_component(
    component: &CompactResponseComponentGeometry,
    leaf_count: u64,
    field_elements_per_leaf: u64,
) -> Result<(), CompactMaskingEntropyError> {
    if component.leaf_count() != leaf_count
        || component.field_element_count_per_leaf() != field_elements_per_leaf
        || component.value_kind() != CompactResponseLeafValueKind::ExtensionField
    {
        return Err(CompactMaskingEntropyError::InvalidContract);
    }
    Ok(())
}

fn checked_add(left: u64, right: u64) -> Result<u64, CompactMaskingEntropyError> {
    left.checked_add(right)
        .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)
}

/// The final CFW response is atomic. Sampling its full-rank terminal values
/// before its translated outer-evaluation hyperplane gives the exact joint
/// distribution while preserving the canonical outer-first wire encoding.
fn simulator_intra_move_ordinal(
    canonical_component_ordinal: u32,
    role_tag: u8,
) -> Result<u32, CompactMaskingEntropyError> {
    match role_tag {
        9 => canonical_component_ordinal
            .checked_add(1)
            .ok_or(CompactMaskingEntropyError::ArithmeticOverflow),
        10 => canonical_component_ordinal
            .checked_sub(1)
            .ok_or(CompactMaskingEntropyError::InvalidContract),
        _ => Ok(canonical_component_ordinal),
    }
}

fn checked_product(values: &[u64]) -> Result<u64, CompactMaskingEntropyError> {
    values.iter().try_fold(1_u64, |product, value| {
        product
            .checked_mul(*value)
            .ok_or(CompactMaskingEntropyError::ArithmeticOverflow)
    })
}

#[cfg(test)]
fn hash_steps(steps: &[CompactMaskingEntropyStep]) -> [u8; 64] {
    let mut bytes = Vec::with_capacity(steps.len() * 48);
    bytes.extend_from_slice(&(steps.len() as u64).to_le_bytes());
    for step in steps {
        bytes.extend_from_slice(&step.ordinal.to_le_bytes());
        bytes.extend_from_slice(&step.verifier_move_ordinal.to_le_bytes());
        encode_kind(&mut bytes, step.kind);
        bytes.extend_from_slice(&step.output_coordinate_count.to_le_bytes());
        encode_image(&mut bytes, step.image);
        bytes.extend_from_slice(&step.conditional_rank.to_le_bytes());
        bytes.extend_from_slice(&step.cumulative_rank.to_le_bytes());
        bytes.extend_from_slice(&step.residual_entropy_dimension.to_le_bytes());
    }
    hash_framed_parts_512(DISCLOSURE_DIGEST_DOMAIN, &[&bytes])
}

#[cfg(test)]
fn encode_image(output: &mut Vec<u8>, image: CompactMaskingDisclosureImage) {
    match image {
        CompactMaskingDisclosureImage::FullCoordinateSpace => output.push(1),
        CompactMaskingDisclosureImage::CoefficientMapImage {
            map_ordinal,
            first_output_coordinate,
        } => {
            output.push(2);
            output.extend_from_slice(&(map_ordinal as u64).to_le_bytes());
            output.extend_from_slice(&first_output_coordinate.to_le_bytes());
        }
        CompactMaskingDisclosureImage::LinearClaimFiber {
            pivot_output_coordinate,
        } => {
            output.push(3);
            output.extend_from_slice(&pivot_output_coordinate.to_le_bytes());
        }
    }
}

#[cfg(test)]
fn hash_contract_binding(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    maps: &CompactMaskingCoefficientMapCertificate,
    disclosure_digest: &[u8; 64],
) -> Result<[u8; 64], CompactMaskingEntropyError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(inputs.verifier_moves.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&(inputs.response_merkle_geometries.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&(maps.maps().len() as u64).to_le_bytes());
    for map in maps.maps() {
        bytes.push(map.coordinate.role as u8);
        bytes.push(map.coordinate.epoch);
        bytes.push(map.coordinate.batch_ordinal);
        bytes.extend_from_slice(&map.coordinate.coordinate.to_le_bytes());
        bytes.extend_from_slice(&map.private_coordinate_count.to_le_bytes());
        bytes.extend_from_slice(&map.view_coordinate_count.to_le_bytes());
    }
    Ok(hash_framed_parts_512(
        CONTRACT_BINDING_DOMAIN,
        &[&bytes, disclosure_digest],
    ))
}

fn hash_transcript_prefix(
    coefficient_map_binding: [u8; 64],
    identity: CompactMaskingAttemptIdentity,
    transcript: &CompactMaskingEntropyTranscript,
    next_move_ordinal: usize,
) -> [u8; 64] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&identity.binding_bytes());
    bytes.extend_from_slice(&(next_move_ordinal as u64).to_le_bytes());
    bytes.push(u8::from(
        transcript.cfw_constraint_combining_challenge.is_some(),
    ));
    if let Some(challenge) = transcript.cfw_constraint_combining_challenge {
        for coordinate in
            <CompactChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                &challenge,
            )
        {
            bytes.extend_from_slice(&coordinate.as_canonical_u64().to_le_bytes());
        }
    }
    bytes.extend_from_slice(&(transcript.cfw_equality_point.len() as u64).to_le_bytes());
    for coordinate_value in &transcript.cfw_equality_point {
        for coordinate in
            <CompactChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                coordinate_value,
            )
        {
            bytes.extend_from_slice(&coordinate.as_canonical_u64().to_le_bytes());
        }
    }
    bytes.extend_from_slice(&(transcript.cfw_round_challenges.len() as u64).to_le_bytes());
    for challenge in &transcript.cfw_round_challenges {
        for coordinate in
            <CompactChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                challenge,
            )
        {
            bytes.extend_from_slice(&coordinate.as_canonical_u64().to_le_bytes());
        }
    }
    bytes.extend_from_slice(&(transcript.sumcheck_challenges.len() as u64).to_le_bytes());
    for record in &transcript.sumcheck_challenges {
        bytes.extend_from_slice(&[record.epoch, record.batch_ordinal]);
        bytes.extend_from_slice(&(record.challenges.len() as u64).to_le_bytes());
        for challenge in &record.challenges {
            for coordinate in
                <CompactChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                    challenge,
                )
            {
                bytes.extend_from_slice(&coordinate.as_canonical_u64().to_le_bytes());
            }
        }
    }
    bytes.extend_from_slice(&(transcript.query_sets.len() as u64).to_le_bytes());
    for query in &transcript.query_sets {
        bytes.extend_from_slice(&query.logical_verifier_move_ordinal.to_le_bytes());
        bytes.extend_from_slice(&query.distinct_query_group_ordinal.to_le_bytes());
        bytes.extend_from_slice(&(query.indices.len() as u64).to_le_bytes());
        for index in &query.indices {
            bytes.extend_from_slice(&index.to_le_bytes());
        }
    }
    bytes.extend_from_slice(&(transcript.base_fresh_claims.len() as u64).to_le_bytes());
    for claim in &transcript.base_fresh_claims {
        bytes.push(claim.epoch);
        bytes.extend_from_slice(&(claim.coefficients.len() as u64).to_le_bytes());
        for coefficient in &claim.coefficients {
            for coordinate in
                <CompactChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                    coefficient,
                )
            {
                bytes.extend_from_slice(&coordinate.as_canonical_u64().to_le_bytes());
            }
        }
    }
    hash_framed_parts_512(
        "sealed-lattice/proof/compact-masking-entropy-prefix/v2",
        &[&coefficient_map_binding, &bytes],
    )
}

#[cfg(test)]
fn encode_kind(output: &mut Vec<u8>, kind: CompactMaskingDisclosureKind) {
    match kind {
        CompactMaskingDisclosureKind::CrossEpochExplicitPoint => output.push(1),
        CompactMaskingDisclosureKind::CfwOuterAuxiliary => output.push(2),
        CompactMaskingDisclosureKind::CfwOuterRound { round_ordinal } => {
            output.push(3);
            output.extend_from_slice(&round_ordinal.to_le_bytes());
        }
        CompactMaskingDisclosureKind::CfwOuterEvaluations => output.push(4),
        CompactMaskingDisclosureKind::CfwInnerTerminal => output.push(5),
        CompactMaskingDisclosureKind::WhirSumcheckAuxiliary {
            epoch,
            batch_ordinal,
        } => {
            output.extend_from_slice(&[6, epoch, batch_ordinal]);
        }
        CompactMaskingDisclosureKind::WhirSumcheckRound {
            epoch,
            batch_ordinal,
            round_ordinal,
        } => {
            output.extend_from_slice(&[7, epoch, batch_ordinal]);
            output.extend_from_slice(&round_ordinal.to_le_bytes());
        }
        CompactMaskingDisclosureKind::SourceQueries {
            epoch,
            source_ordinal,
        } => output.extend_from_slice(&[8, epoch, source_ordinal]),
        CompactMaskingDisclosureKind::CarriedMaskQueries {
            epoch,
            group_ordinal,
            contract_role_tag,
        } => output.extend_from_slice(&[9, epoch, group_ordinal, contract_role_tag]),
        CompactMaskingDisclosureKind::BaseFreshClaim { epoch } => {
            output.extend_from_slice(&[10, epoch]);
        }
        CompactMaskingDisclosureKind::BaseBlindedSourceMessage { epoch } => {
            output.extend_from_slice(&[11, epoch]);
        }
        CompactMaskingDisclosureKind::BaseBlindedSourceRandomness { epoch } => {
            output.extend_from_slice(&[12, epoch]);
        }
        CompactMaskingDisclosureKind::BaseBlindedMaskGroup {
            epoch,
            group_ordinal,
        } => output.extend_from_slice(&[13, epoch, group_ordinal]),
        CompactMaskingDisclosureKind::FreshSourceQueries { epoch } => {
            output.extend_from_slice(&[14, epoch]);
        }
        CompactMaskingDisclosureKind::FreshMaskQueries {
            epoch,
            group_ordinal,
        } => output.extend_from_slice(&[15, epoch, group_ordinal]),
    }
}

#[cfg(test)]
pub(crate) fn selected_test_compact_masking_entropy_certificate(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
) -> Result<CompactMaskingEntropyCertificate, CompactMaskingEntropyError> {
    let transcript = selected_test_transcript(inputs)?;
    certify_compact_masking_entropy(inputs, coefficient_maps, &transcript)
}

#[cfg(test)]
fn selected_test_transcript(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
) -> Result<CompactMaskingEntropyTranscript, CompactMaskingEntropyError> {
    let cfw_round_count = inputs.cfw_configuration.geometry().sumcheck_round_count();
    let cfw_constraint_combining_challenge = CompactChallengeField::from_u64(2_001);
    let cfw_equality_point = (0..cfw_round_count)
        .map(|ordinal| {
            u64::try_from(ordinal)
                .map(|ordinal| CompactChallengeField::from_u64(2_101 + ordinal))
                .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cfw_round_challenges = (0..cfw_round_count)
        .map(|ordinal| {
            Ok(CompactChallengeField::from_u64(
                3 + u64::try_from(ordinal)
                    .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut sumcheck_challenges = Vec::new();
    for epoch in inputs.whir_epochs {
        for group in epoch
            .internal_mask_groups
            .iter()
            .filter(|group| group.role_tag == 4)
        {
            sumcheck_challenges.push(CompactMaskingSumcheckChallenges::new(
                epoch.epoch,
                group.coordinate,
                (0..group.width)
                    .map(|ordinal| {
                        CompactChallengeField::from_u64(
                            1_000
                                + 100 * u64::from(epoch.epoch)
                                + 10 * u64::from(group.coordinate)
                                + ordinal,
                        )
                    })
                    .collect(),
            ));
        }
    }
    let mut query_sets = Vec::new();
    for verifier_move in inputs.verifier_moves {
        for (group_index, group) in verifier_move
            .message_geometry
            .distinct_query_groups()
            .iter()
            .enumerate()
        {
            query_sets.push(CompactMaskingQuerySet::new(
                verifier_move.ordinal,
                u32::try_from(group_index)
                    .map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?,
                (0..group.query_count()).collect(),
            ));
        }
    }
    let shared_component = inputs
        .response_merkle_geometries
        .iter()
        .zip(inputs.response_component_roles)
        .flat_map(|(geometry, roles)| geometry.components().iter().zip(roles))
        .find(|(_, role)| role.role_tag == 5)
        .ok_or(CompactMaskingEntropyError::InvalidContract)?
        .0;
    let shared_refs = component_query_refs(shared_component);
    let first = query_sets
        .iter()
        .find(|query| {
            query.logical_verifier_move_ordinal == shared_refs[0].0
                && query.distinct_query_group_ordinal == shared_refs[0].1
        })
        .ok_or(CompactMaskingEntropyError::MissingTranscriptInput)?
        .indices
        .clone();
    let second = query_sets
        .iter_mut()
        .find(|query| {
            query.logical_verifier_move_ordinal == shared_refs[1].0
                && query.distinct_query_group_ordinal == shared_refs[1].1
        })
        .ok_or(CompactMaskingEntropyError::MissingTranscriptInput)?;
    let shift =
        u64::try_from(first.len()).map_err(|_| CompactMaskingEntropyError::ArithmeticOverflow)?;
    second.indices = (shift..shift + shift).collect();

    let mut base_fresh_claims = Vec::new();
    for epoch in inputs.whir_epochs {
        let mut coefficients = vec![
            CompactChallengeField::ZERO;
            usize::try_from(base_fresh_message_dimension(epoch)?).map_err(
                |_| CompactMaskingEntropyError::ArithmeticOverflow
            )?
        ];
        coefficients[0] = CompactChallengeField::ONE;
        base_fresh_claims.push(CompactBaseFreshClaimCoefficients::new(
            epoch.epoch,
            coefficients,
        ));
    }
    Ok(CompactMaskingEntropyTranscript::new(
        Some(cfw_constraint_combining_challenge),
        cfw_equality_point,
        cfw_round_challenges,
        sumcheck_challenges,
        query_sets,
        base_fresh_claims,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_masking_coefficient_maps::derive_compact_masking_coefficient_map_certificate;
    use crate::bgv::proof_suite::compact_proof_contract::selected_compact_public_key_proof_contract;
    use crate::bgv::proof_suite::field::ProofBaseFieldElement;

    fn selected() -> (
        super::super::compact_proof_contract::CompactPublicKeyProofContract,
        CompactMaskingCoefficientMapCertificate,
    ) {
        let contract = selected_compact_public_key_proof_contract().expect("selected contract");
        let maps = derive_compact_masking_coefficient_map_certificate(contract.verifier_inputs())
            .expect("selected coefficient maps");
        (contract, maps)
    }

    fn selected_adversarial_message(
        inputs: &CompactPublicKeyVerifierInputs<'_>,
        move_ordinal: usize,
    ) -> DecodedFixedUniformVerifierMessage {
        let geometry = &inputs.verifier_moves[move_ordinal].message_geometry;
        let extension_elements = (0..geometry.extension_output_count())
            .map(|coordinate_ordinal| {
                crate::bgv::proof_suite::field::ProofChallengeExtensionElement::from_canonical_coordinates(
                    [1 + coordinate_ordinal, 1, 0, 0, 0],
                )
                .expect("small extension value is canonical")
            })
            .collect();
        let base_field_elements = (0..geometry.base_field_output_count())
            .map(|coordinate_ordinal| {
                ProofBaseFieldElement::from_canonical(3 + coordinate_ordinal)
                    .expect("small base-field value is canonical")
            })
            .collect();
        let distinct_query_groups = geometry
            .distinct_query_groups()
            .iter()
            .map(|group| (0..group.query_count()).collect())
            .collect();
        DecodedFixedUniformVerifierMessage::from_adversarial_values(
            geometry,
            extension_elements,
            base_field_elements,
            distinct_query_groups,
        )
        .expect("typed malicious-verifier message matches the selected geometry")
    }

    #[test]
    fn selected_disjoint_schedule_has_exact_joint_conditional_entropy() {
        let (contract, maps) = selected();
        let inputs = contract.verifier_inputs();
        let certificate = selected_test_compact_masking_entropy_certificate(&inputs, &maps)
            .expect("selected entropy certificate");

        assert_eq!(certificate.private_coordinate_count(), 230_488);
        assert_eq!(certificate.joint_disclosure_rank(), 230_324);
        assert_eq!(certificate.residual_conditional_entropy_dimension(), 164);
        assert_eq!(certificate.shared_cross_epoch_query_overlap(), 0);
        certificate
            .check(&maps)
            .expect("certificate remains intrinsically valid");
    }

    #[test]
    fn selected_commitment_census_binds_one_shared_root_to_two_query_consumers() {
        let (contract, maps) = selected();
        let inputs = contract.verifier_inputs();
        let commitments = maps.construction_commitment_embeddings();
        let external_mask_root_count = commitments
            .iter()
            .filter(|embedding| matches!(embedding.component_role.role_tag, 2 | 4 | 5))
            .count();
        let whir_internal_commitment_count = commitments.len() - external_mask_root_count;
        assert_eq!(commitments.len(), 45);
        assert_eq!(whir_internal_commitment_count, 42);
        assert_eq!(external_mask_root_count, 3);

        let shared_component = inputs
            .response_merkle_geometries
            .iter()
            .zip(inputs.response_component_roles)
            .flat_map(|(geometry, roles)| geometry.components().iter().zip(roles))
            .find(|(_, role)| role.role_tag == 5)
            .expect("shared cross-epoch component")
            .0;
        let query_consumers = component_query_refs(shared_component);
        validate_shared_commitment_union_root(&maps, &query_consumers)
            .expect("one shared root binds both query consumers");

        let swapped_query_consumers = [query_consumers[1], query_consumers[0]];
        assert_eq!(
            validate_shared_commitment_union_root(&maps, &swapped_query_consumers),
            Err(CompactMaskingEntropyError::InvalidCoefficientMap)
        );
        let collapsed_query_consumers = [query_consumers[0], query_consumers[0]];
        assert_eq!(
            validate_shared_commitment_union_root(&maps, &collapsed_query_consumers),
            Err(CompactMaskingEntropyError::InvalidCoefficientMap)
        );
    }

    #[test]
    fn cross_epoch_rank_rejects_wrong_witness_and_dimensions() {
        let (contract, maps) = selected();
        let cross_epoch = contract.verifier_inputs().cfw_configuration.cross_epoch();
        let mut map = maps
            .maps()
            .iter()
            .find(|map| map.coordinate.role == CompactMaskingViewRole::ExplicitPoint)
            .expect("explicit-point map")
            .clone();
        assert_eq!(
            validated_cross_epoch_rank(
                &map,
                cross_epoch.copied_element_count,
                cross_epoch.point_coordinate_count,
            ),
            Ok(2),
        );

        map.surjectivity = CompactSurjectivityWitness::CoordinateIdentity;
        assert_eq!(
            validated_cross_epoch_rank(
                &map,
                cross_epoch.copied_element_count,
                cross_epoch.point_coordinate_count,
            ),
            Err(CompactMaskingEntropyError::InvalidCoefficientMap),
        );

        map.surjectivity = CompactSurjectivityWitness::CrossEpochTwoMaskCorrection;
        map.private_coordinate_count -= 1;
        assert_eq!(
            validated_cross_epoch_rank(
                &map,
                cross_epoch.copied_element_count,
                cross_epoch.point_coordinate_count,
            ),
            Err(CompactMaskingEntropyError::InvalidCoefficientMap),
        );
    }

    #[test]
    fn streaming_query_steps_read_only_the_current_and_retained_query_sets() {
        let (contract, maps) = selected();
        let inputs = contract.verifier_inputs();
        let shared_component = inputs
            .response_merkle_geometries
            .iter()
            .zip(inputs.response_component_roles)
            .flat_map(|(geometry, roles)| geometry.components().iter().zip(roles))
            .find(|(_, role)| role.role_tag == 5)
            .expect("shared cross-epoch component")
            .0;
        let refs = component_query_refs(shared_component);
        let mut full_transcript =
            selected_test_transcript(&inputs).expect("selected entropy transcript");
        let retained_first_indices = unique_query_set(&full_transcript, refs[0].0, refs[0].1)
            .expect("first shared query set")
            .indices
            .clone();
        full_transcript
            .query_sets
            .iter_mut()
            .find(|query| {
                query.logical_verifier_move_ordinal == refs[1].0
                    && query.distinct_query_group_ordinal == refs[1].1
            })
            .expect("second shared query set")
            .indices = retained_first_indices.clone();
        let transcript_through = |move_ordinal| {
            CompactMaskingEntropyTranscript::new(
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                full_transcript
                    .query_sets
                    .iter()
                    .filter(|query| query.logical_verifier_move_ordinal <= move_ordinal)
                    .cloned()
                    .collect(),
                Vec::new(),
            )
        };

        let mut move_zero_steps = Vec::new();
        append_query_steps_for_move(
            &inputs,
            &maps,
            &transcript_through(0),
            0,
            &mut move_zero_steps,
        )
        .expect("move zero does not require future query sets");
        assert!(move_zero_steps.is_empty());

        let mut first_steps = Vec::new();
        append_query_steps_for_move(
            &inputs,
            &maps,
            &transcript_through(refs[0].0),
            refs[0].0,
            &mut first_steps,
        )
        .expect("first shared arm does not require the future second arm");
        let first_shared_step = first_steps
            .iter()
            .find(|step| {
                matches!(
                    step.kind,
                    CompactMaskingDisclosureKind::CarriedMaskQueries {
                        epoch: 1,
                        contract_role_tag: 1,
                        ..
                    }
                )
            })
            .expect("first shared disclosure");
        assert!(pending_step_conditional_rank(first_shared_step).expect("first rank") > 0);
        assert!(!first_steps.iter().any(|step| {
            matches!(
                step.kind,
                CompactMaskingDisclosureKind::CarriedMaskQueries {
                    epoch: 2,
                    contract_role_tag: 1,
                    ..
                }
            )
        }));

        let second_arm_transcript = transcript_through(refs[1].0);
        let mut second_steps = Vec::new();
        append_query_steps_for_move(
            &inputs,
            &maps,
            &second_arm_transcript,
            refs[1].0,
            &mut second_steps,
        )
        .expect("second shared arm conditions on the retained first arm");
        let second_shared_step = second_steps
            .iter()
            .find(|step| {
                matches!(
                    step.kind,
                    CompactMaskingDisclosureKind::CarriedMaskQueries {
                        epoch: 2,
                        contract_role_tag: 1,
                        ..
                    }
                )
            })
            .expect("second shared disclosure");
        assert_eq!(pending_step_conditional_rank(second_shared_step), Ok(0),);
        assert!(!second_steps.iter().any(|step| {
            matches!(
                step.kind,
                CompactMaskingDisclosureKind::CarriedMaskQueries {
                    epoch: 1,
                    contract_role_tag: 1,
                    ..
                }
            )
        }));
        let second_query_positions = query_positions_for_disclosure(
            &inputs,
            &second_arm_transcript,
            second_shared_step.kind,
        )
        .expect("the shared component resolves its main-epoch query arm");
        assert_eq!(second_query_positions.preceding, retained_first_indices);
        assert_eq!(second_query_positions.current, retained_first_indices);
    }

    #[test]
    fn streaming_base_reveal_reads_only_the_current_epoch_claim() {
        let (contract, _) = selected();
        let inputs = contract.verifier_inputs();
        let mut first_epoch_transcript =
            selected_test_transcript(&inputs).expect("selected entropy transcript");
        first_epoch_transcript
            .base_fresh_claims
            .retain(|claim| claim.epoch() == 1);
        assert_eq!(first_epoch_transcript.base_fresh_claims.len(), 1);

        let mut first_epoch_steps = Vec::new();
        append_base_reveal_steps_for_epoch(
            &inputs,
            &first_epoch_transcript,
            1,
            &mut first_epoch_steps,
        )
        .expect("first epoch reveal does not require the future epoch claim");
        assert!(!first_epoch_steps.is_empty());
        assert!(
            first_epoch_steps
                .iter()
                .all(|step| step.kind.reveal_epoch() == Some(1))
        );
        assert!(first_epoch_steps.iter().any(|step| {
            step.kind == CompactMaskingDisclosureKind::BaseBlindedSourceMessage { epoch: 1 }
        }));
        assert!(first_epoch_steps.iter().any(|step| {
            step.kind == CompactMaskingDisclosureKind::BaseBlindedSourceRandomness { epoch: 1 }
        }));
        assert!(first_epoch_steps.iter().any(|step| {
            matches!(
                step.kind,
                CompactMaskingDisclosureKind::BaseBlindedMaskGroup { epoch: 1, .. }
            )
        }));

        let mut future_epoch_steps = Vec::new();
        assert_eq!(
            append_base_reveal_steps_for_epoch(
                &inputs,
                &first_epoch_transcript,
                2,
                &mut future_epoch_steps,
            ),
            Err(CompactMaskingEntropyError::MissingTranscriptInput)
        );
        assert!(future_epoch_steps.is_empty());
    }

    #[test]
    fn shared_root_overlap_is_conditioned_at_the_second_disclosure() {
        let (contract, maps) = selected();
        let inputs = contract.verifier_inputs();
        let mut transcript = selected_test_transcript(&inputs).expect("selected transcript");
        let shared = inputs
            .response_merkle_geometries
            .iter()
            .zip(inputs.response_component_roles)
            .flat_map(|(geometry, roles)| geometry.components().iter().zip(roles))
            .find(|(_, role)| role.role_tag == 5)
            .expect("shared component")
            .0;
        let refs = component_query_refs(shared);
        let first = unique_query_set(&transcript, refs[0].0, refs[0].1)
            .expect("first query")
            .indices
            .clone();
        transcript
            .query_sets
            .iter_mut()
            .find(|query| {
                query.logical_verifier_move_ordinal == refs[1].0
                    && query.distinct_query_group_ordinal == refs[1].1
            })
            .expect("second query")
            .indices = first;
        let certificate = certify_compact_masking_entropy(&inputs, &maps, &transcript)
            .expect("overlapping schedule certificate");

        assert_eq!(certificate.shared_cross_epoch_query_overlap(), 399);
        assert_eq!(certificate.joint_disclosure_rank(), 229_526);
        assert_eq!(certificate.residual_conditional_entropy_dimension(), 962);
        let shared_steps = certificate
            .steps()
            .iter()
            .filter(|step| {
                matches!(
                    step.kind(),
                    CompactMaskingDisclosureKind::CarriedMaskQueries {
                        contract_role_tag: 1,
                        ..
                    }
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(shared_steps.len(), 2);
        assert_eq!(shared_steps[0].conditional_rank(), 798);
        assert_eq!(shared_steps[1].conditional_rank(), 0);
    }

    #[test]
    fn final_identity_reveals_precede_and_condition_fresh_query_rows() {
        let (contract, maps) = selected();
        let inputs = contract.verifier_inputs();
        let certificate = selected_test_compact_masking_entropy_certificate(&inputs, &maps)
            .expect("selected entropy certificate");
        for epoch in 1..=2 {
            let query = certificate
                .steps()
                .iter()
                .find(|step| {
                    step.kind() == CompactMaskingDisclosureKind::FreshSourceQueries { epoch }
                })
                .expect("fresh source query");
            let reveal = certificate
                .steps()
                .iter()
                .find(|step| {
                    step.kind()
                        == CompactMaskingDisclosureKind::BaseBlindedSourceRandomness { epoch }
                })
                .expect("fresh source randomness reveal");
            assert!(reveal.ordinal() < query.ordinal());
            assert!(reveal.conditional_rank() > 0);
            assert_eq!(query.conditional_rank(), 0);
        }
    }

    #[test]
    fn selected_first_epoch_final_queries_identify_deferred_union_transport() {
        let (contract, maps) = selected();
        let inputs = contract.verifier_inputs();
        let transcript = selected_test_transcript(&inputs).expect("selected transcript");
        let final_query_move = inputs
            .verifier_moves
            .iter()
            .find(|verifier_move| {
                verifier_move
                    .role_coordinates
                    .iter()
                    .any(|role| role.role_tag == 11 && role.epoch == 1 && role.batch_ordinal == 0)
            })
            .expect("first-epoch final-query move");
        let mut steps = Vec::new();
        append_query_steps_for_move(
            &inputs,
            &maps,
            &transcript,
            final_query_move.ordinal,
            &mut steps,
        )
        .expect("first-epoch final queries derive from the selected contract");

        let mut deferred_union_count = 0;
        let mut deferred_output_coordinate_count = 0_u64;
        let mut immediate_component_count = 0;
        let mut verifier_selected_leaf_count = 0_usize;
        for step in &steps {
            let (_geometry, component) =
                query_component_for_disclosure(&inputs, step.kind).expect("query component");
            let positions = query_positions_for_disclosure(&inputs, &transcript, step.kind)
                .expect("query positions");
            assert!(positions.preceding.is_empty());
            verifier_selected_leaf_count += positions.current.len();
            match component.query_selection() {
                CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                    logical_verifier_move_ordinal,
                    ..
                } => {
                    assert_eq!(logical_verifier_move_ordinal, final_query_move.ordinal);
                    immediate_component_count += 1;
                }
                CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                    first_logical_verifier_move_ordinal,
                    second_logical_verifier_move_ordinal,
                    ..
                } => {
                    assert_eq!(
                        first_logical_verifier_move_ordinal,
                        final_query_move.ordinal
                    );
                    assert!(second_logical_verifier_move_ordinal > final_query_move.ordinal);
                    deferred_union_count += 1;
                    deferred_output_coordinate_count += step.output_coordinate_count;
                }
                CompactResponseQuerySelection::Unqueried
                | CompactResponseQuerySelection::EveryLeaf => {
                    panic!("final query must use verifier-selected component coordinates")
                }
            }
        }
        assert_eq!(steps.len(), 18);
        assert_eq!(immediate_component_count, 17);
        assert_eq!(deferred_union_count, 1);
        assert_eq!(deferred_output_coordinate_count, 798);
        assert_eq!(verifier_selected_leaf_count, 7_080);
    }

    #[test]
    fn production_final_query_gate_accepts_immediate_and_deferred_committed_leaves() {
        let (contract, maps) = selected();
        let inputs = contract.verifier_inputs();
        let [pre_challenge_epoch, _main_epoch] = inputs.whir_epochs else {
            panic!("the selected contract has two WHIR epochs")
        };
        let final_query_move_ordinal = inputs
            .verifier_moves
            .iter()
            .find(|verifier_move| {
                verifier_move
                    .role_coordinates
                    .iter()
                    .any(|role| role.role_tag == 11 && role.epoch == pre_challenge_epoch.epoch)
            })
            .expect("first-epoch final-query move")
            .ordinal;
        let messages = (0..=usize::try_from(final_query_move_ordinal).unwrap())
            .map(|move_index| selected_adversarial_message(&inputs, move_index))
            .collect::<Vec<_>>();
        let mut claim_coefficients = vec![
            CompactChallengeField::ZERO;
            usize::try_from(
                base_fresh_message_dimension(pre_challenge_epoch).expect("base message dimension"),
            )
            .unwrap()
        ];
        claim_coefficients[0] = CompactChallengeField::ONE;
        let identity = CompactMaskingAttemptIdentity::new([7; 32], 0, [11; 64]);
        let base_combination_move_ordinal = inputs
            .verifier_moves
            .iter()
            .find(|verifier_move| {
                verifier_move
                    .role_coordinates
                    .iter()
                    .any(|role| role.role_tag == 10 && role.epoch == pre_challenge_epoch.epoch)
            })
            .expect("first-epoch base-combination move")
            .ordinal;
        let verified_reveal = verify_selected_compact_whir_base_reveal_masking(
            contract.verifier_inputs(),
            &maps,
            identity,
            &messages[..=usize::try_from(base_combination_move_ordinal).unwrap()],
            None,
            pre_challenge_epoch.epoch,
            &claim_coefficients,
        )
        .expect("the compiler-derived base reveal masking is verified");
        let (authority, _reveal_steps, final_query_steps) =
            replay_selected_compact_masking_prefix_with_base_claim(
                contract.verifier_inputs(),
                &maps,
                identity,
                &messages,
                None,
                pre_challenge_epoch.epoch,
                &claim_coefficients,
            )
            .expect("the production final-query prefix replays");

        let mut query_leaves = Vec::new();
        for step in &final_query_steps {
            let positions = query_positions_for_disclosure(
                &authority.inputs,
                &authority.transcript,
                step.kind(),
            )
            .expect("final query positions");
            assert!(positions.preceding.is_empty());
            let (geometry, component) =
                query_component_for_disclosure(&authority.inputs, step.kind())
                    .expect("final query component");
            let value_count = usize::try_from(component.field_element_count_per_leaf()).unwrap();
            assert_eq!(
                usize::try_from(step.output_coordinate_count()).unwrap(),
                positions.current.len() * value_count
            );
            for query_position in positions.current {
                query_leaves.push(
                    CompactMaskingQueryLeaf::new(
                        geometry.response_ordinal(),
                        component.first_leaf_ordinal() + *query_position,
                        vec![CompactChallengeField::ZERO; value_count],
                    )
                    .expect("canonical zero query leaf"),
                );
            }
        }

        let final_fold = inputs
            .whir_folds
            .iter()
            .find(|fold| fold.epoch == pre_challenge_epoch.epoch && fold.batch_ordinal == 3)
            .expect("final pre-challenge fold");
        let fresh_source_mirror_coefficients =
            vec![
                CompactChallengeField::ZERO;
                usize::try_from(final_fold.message_length + final_fold.hiding_randomness_length,)
                    .unwrap()
            ];
        let fresh_mask_mirror_coefficients = pre_challenge_epoch
            .external_mask_groups
            .iter()
            .chain(&pre_challenge_epoch.internal_mask_groups)
            .map(|group| {
                vec![
                    CompactChallengeField::ZERO;
                    usize::try_from(group.width * (group.message_length + group.randomness_length),)
                        .unwrap()
                ]
            })
            .collect::<Vec<_>>();
        let verify_query_leaves = |query_leaves: &[CompactMaskingQueryLeaf]| {
            verify_selected_compact_whir_base_final_query_masking(
                contract.verifier_inputs(),
                &maps,
                identity,
                &messages,
                None,
                pre_challenge_epoch.epoch,
                &verified_reveal,
                &fresh_source_mirror_coefficients,
                &fresh_mask_mirror_coefficients,
                query_leaves,
            )
        };
        let verified_base_prefix = verify_query_leaves(&query_leaves)
            .expect("the final gate accepts immediate and deferred committed query leaves");

        let [_pre_challenge_epoch, main_epoch] = inputs.whir_epochs else {
            panic!("the selected compact contract has both WHIR epochs")
        };
        let mut main_auxiliary_response_ordinals = inputs
            .response_component_roles
            .iter()
            .enumerate()
            .filter_map(|(response_ordinal, roles)| {
                roles
                    .iter()
                    .any(|role| {
                        role.role_tag == 11
                            && role.epoch == main_epoch.epoch
                            && role.batch_ordinal == 0
                            && role.round_ordinal == 0
                    })
                    .then_some(response_ordinal)
            });
        let main_auxiliary_response_ordinal = main_auxiliary_response_ordinals
            .next()
            .expect("the selected contract has an initial main-WHIR auxiliary response");
        assert!(main_auxiliary_response_ordinals.next().is_none());
        let main_completed_messages = (0..main_auxiliary_response_ordinal)
            .map(|move_index| selected_adversarial_message(&inputs, move_index))
            .collect::<Vec<_>>();
        assert!(matches!(
            replay_selected_compact_masking_prefix(
                contract.verifier_inputs(),
                &maps,
                identity,
                &main_completed_messages,
                None,
            ),
            Err(CompactMaskingEntropyError::InvalidCoefficientVector)
        ));
        let mut main_authority = replay_selected_compact_masking_prefix(
            contract.verifier_inputs(),
            &maps,
            identity,
            &main_completed_messages,
            Some(&verified_base_prefix),
        )
        .expect("the verified base prefix restores the initial main-WHIR masking state");
        let main_auxiliary_steps = main_authority
            .authorize_next_response(None)
            .expect("the initial main-WHIR auxiliary response is authorized")
            .to_vec();
        let [main_auxiliary_step] = main_auxiliary_steps.as_slice() else {
            panic!("the initial main-WHIR response has one auxiliary masking view")
        };
        assert_eq!(
            main_auxiliary_step.kind(),
            CompactMaskingDisclosureKind::WhirSumcheckAuxiliary {
                epoch: main_epoch.epoch,
                batch_ordinal: 0,
            }
        );
        let main_auxiliary_request = main_authority
            .prepare_coefficient_image(main_auxiliary_step, &[], None)
            .expect("the main-WHIR auxiliary coefficient image derives");
        let main_independent_coordinates = (0..main_auxiliary_step.conditional_rank())
            .map(|coordinate_ordinal| CompactChallengeField::from_u64(1_401 + coordinate_ordinal))
            .collect::<Vec<_>>();
        let [main_auxiliary_target] = main_authority
            .execute_coefficient_image(
                main_auxiliary_step,
                &main_auxiliary_request,
                &main_independent_coordinates,
            )
            .expect("the main-WHIR auxiliary coefficient image executes")
            .try_into()
            .expect("the main-WHIR auxiliary view has one coordinate");
        verify_selected_compact_whir_sumcheck_auxiliary_masking(
            contract.verifier_inputs(),
            &maps,
            identity,
            &main_completed_messages,
            Some(&verified_base_prefix),
            CompactWhirSumcheckBatchCoordinate::new(main_epoch.epoch, 0),
            main_auxiliary_target,
        )
        .expect("the production gate accepts main WHIR only after the verified base prefix");

        let main_final_query_move_ordinal = inputs
            .verifier_moves
            .iter()
            .find(|verifier_move| {
                verifier_move
                    .role_coordinates
                    .iter()
                    .any(|role| role.role_tag == 11 && role.epoch == main_epoch.epoch)
            })
            .expect("main-epoch final-query move")
            .ordinal;
        let main_messages = (0..=usize::try_from(main_final_query_move_ordinal).unwrap())
            .map(|move_index| selected_adversarial_message(&inputs, move_index))
            .collect::<Vec<_>>();
        let mut main_claim_coefficients = vec![
            CompactChallengeField::ZERO;
            usize::try_from(
                base_fresh_message_dimension(main_epoch).expect("main base message dimension"),
            )
            .unwrap()
        ];
        main_claim_coefficients[0] = CompactChallengeField::ONE;
        let main_base_combination_move_ordinal = inputs
            .verifier_moves
            .iter()
            .find(|verifier_move| {
                verifier_move
                    .role_coordinates
                    .iter()
                    .any(|role| role.role_tag == 10 && role.epoch == main_epoch.epoch)
            })
            .expect("main-epoch base-combination move")
            .ordinal;
        let verified_main_reveal = verify_selected_compact_whir_base_reveal_masking(
            contract.verifier_inputs(),
            &maps,
            identity,
            &main_messages[..=usize::try_from(main_base_combination_move_ordinal).unwrap()],
            Some(&verified_base_prefix),
            main_epoch.epoch,
            &main_claim_coefficients,
        )
        .expect("the main base reveal masking replays from the verified first-epoch prefix");
        let (main_authority, _main_reveal_steps, main_final_query_steps) =
            replay_selected_compact_masking_prefix_with_base_claim(
                contract.verifier_inputs(),
                &maps,
                identity,
                &main_messages,
                Some(&verified_base_prefix),
                main_epoch.epoch,
                &main_claim_coefficients,
            )
            .expect("the main final-query prefix replays");
        let mut main_query_leaves = Vec::new();
        let mut main_shared_arm_count = 0_u64;
        for step in &main_final_query_steps {
            let positions = query_positions_for_disclosure(
                &main_authority.inputs,
                &main_authority.transcript,
                step.kind(),
            )
            .expect("main final-query positions");
            let (geometry, component) =
                query_component_for_disclosure(&main_authority.inputs, step.kind())
                    .expect("main final-query component");
            let mut union_positions = positions.preceding.to_vec();
            union_positions.extend_from_slice(positions.current);
            union_positions.sort_unstable();
            union_positions.dedup();
            if !positions.preceding.is_empty() {
                assert!(matches!(
                    step.kind(),
                    CompactMaskingDisclosureKind::CarriedMaskQueries {
                        epoch: 2,
                        contract_role_tag: 1,
                        ..
                    }
                ));
                main_shared_arm_count += 1;
            }
            let value_count = usize::try_from(component.field_element_count_per_leaf()).unwrap();
            for query_position in union_positions {
                main_query_leaves.push(
                    CompactMaskingQueryLeaf::new(
                        geometry.response_ordinal(),
                        component.first_leaf_ordinal() + query_position,
                        vec![CompactChallengeField::ZERO; value_count],
                    )
                    .expect("canonical zero main query leaf"),
                );
            }
        }
        assert_eq!(main_shared_arm_count, 1);
        let main_final_fold = inputs
            .whir_folds
            .iter()
            .find(|fold| fold.epoch == main_epoch.epoch && fold.batch_ordinal == 3)
            .expect("final main fold");
        let main_fresh_source_mirror_coefficients = vec![
            CompactChallengeField::ZERO;
            usize::try_from(
                main_final_fold.message_length + main_final_fold.hiding_randomness_length,
            )
            .unwrap()
        ];
        let main_fresh_mask_mirror_coefficients = main_epoch
            .external_mask_groups
            .iter()
            .chain(&main_epoch.internal_mask_groups)
            .map(|group| {
                vec![
                    CompactChallengeField::ZERO;
                    usize::try_from(group.width * (group.message_length + group.randomness_length),)
                        .unwrap()
                ]
            })
            .collect::<Vec<_>>();
        verify_selected_compact_whir_base_final_query_masking(
            contract.verifier_inputs(),
            &maps,
            identity,
            &main_messages,
            Some(&verified_base_prefix),
            main_epoch.epoch,
            &verified_main_reveal,
            &main_fresh_source_mirror_coefficients,
            &main_fresh_mask_mirror_coefficients,
            &main_query_leaves,
        )
        .expect("the main final query accepts the conditioned shared-root second arm");

        let duplicate_response_ordinal = query_leaves[0].response_ordinal;
        let duplicate_leaf_ordinal = query_leaves[0].leaf_ordinal;
        let duplicate_value_count = query_leaves[0].values.len();
        query_leaves.push(
            CompactMaskingQueryLeaf::new(
                duplicate_response_ordinal,
                duplicate_leaf_ordinal,
                vec![CompactChallengeField::ZERO; duplicate_value_count],
            )
            .unwrap(),
        );
        assert!(matches!(
            verify_query_leaves(&query_leaves),
            Err(CompactMaskingEntropyError::DuplicateTranscriptInput)
        ));
        query_leaves.pop();

        query_leaves.pop();
        assert!(matches!(
            verify_query_leaves(&query_leaves),
            Err(CompactMaskingEntropyError::MissingTranscriptInput)
        ));
    }

    #[test]
    fn hostile_query_coordinates_and_cfw_terminal_challenge_refuse() {
        let (contract, maps) = selected();
        let inputs = contract.verifier_inputs();
        let mut duplicate = selected_test_transcript(&inputs).expect("selected transcript");
        duplicate.query_sets[0].indices[1] = duplicate.query_sets[0].indices[0];
        assert_eq!(
            certify_compact_masking_entropy(&inputs, &maps, &duplicate),
            Err(CompactMaskingEntropyError::InvalidQuerySet)
        );

        let mut invalid_challenge = selected_test_transcript(&inputs).expect("selected transcript");
        *invalid_challenge
            .cfw_round_challenges
            .last_mut()
            .expect("last challenge") = CompactChallengeField::ZERO;
        assert_eq!(
            certify_compact_masking_entropy(&inputs, &maps, &invalid_challenge),
            Err(CompactMaskingEntropyError::InvalidChallenge)
        );
    }

    #[test]
    fn simulator_cursor_rejects_reordering_and_in_place_reset_reuse() {
        let (contract, maps) = selected();
        let inputs = contract.verifier_inputs();
        let certificate = selected_test_compact_masking_entropy_certificate(&inputs, &maps)
            .expect("selected entropy certificate");
        let identity = CompactMaskingAttemptIdentity::new([7; 32], 0, [11; 64]);
        let mut cursor = certificate.begin_disclosures(identity);
        assert_eq!(
            certificate
                .verify_simulator_disclosure(&mut cursor, identity, &certificate.steps()[1],),
            Err(CompactMaskingEntropyError::DisclosureOutOfOrder)
        );
        certificate
            .verify_simulator_disclosure(&mut cursor, identity, &certificate.steps()[0])
            .expect("first disclosure");
        let reset_identity = CompactMaskingAttemptIdentity::new([7; 32], 1, [11; 64]);
        assert_eq!(
            certificate.verify_simulator_disclosure(
                &mut cursor,
                reset_identity,
                &certificate.steps()[1],
            ),
            Err(CompactMaskingEntropyError::AttemptIdentityMismatch)
        );

        let mut replay = certificate.begin_disclosures(reset_identity);
        for step in certificate.steps() {
            certificate
                .verify_simulator_disclosure(&mut replay, reset_identity, step)
                .expect("ordered replay under new reset identity");
        }
        replay
            .finish(&certificate, reset_identity)
            .expect("ordered replay consumes the complete disclosure cursor");
    }

    #[test]
    fn entropy_terminal_rejects_incomplete_authority_and_tampered_cursor() {
        let (contract, maps) = selected();
        let inputs = contract.verifier_inputs();
        let identity = CompactMaskingAttemptIdentity::new([9; 32], 0, [13; 64]);
        let authority = CompactMaskingEntropyAuthority::begin(inputs, &maps, identity)
            .expect("selected streaming entropy authority begins");
        assert_eq!(
            authority.finish(),
            Err(CompactMaskingEntropyError::WrongAuthorityPhase)
        );

        let certificate =
            selected_test_compact_masking_entropy_certificate(&contract.verifier_inputs(), &maps)
                .expect("selected entropy certificate");
        assert_eq!(
            certificate
                .begin_disclosures(identity)
                .finish(&certificate, identity),
            Err(CompactMaskingEntropyError::DisclosureOutOfOrder)
        );

        let mut tampered = certificate.begin_disclosures(identity);
        tampered.next_step_ordinal = certificate.steps.len();
        tampered.cumulative_rank = certificate.joint_disclosure_rank;
        tampered.disclosure_digest[0] ^= 1;
        assert_eq!(
            tampered.finish(&certificate, identity),
            Err(CompactMaskingEntropyError::CertificateMismatch)
        );
    }

    #[test]
    fn conditional_image_prefix_binding_changes_across_attempt_resets() {
        let (contract, maps) = selected();
        let transcript =
            selected_test_transcript(&contract.verifier_inputs()).expect("selected transcript");
        let identity = CompactMaskingAttemptIdentity::new([7; 32], 0, [11; 64]);
        let reset_identity = CompactMaskingAttemptIdentity::new([7; 32], 1, [11; 64]);

        assert_ne!(
            hash_transcript_prefix(maps.certificate_digest(), identity, &transcript, 5),
            hash_transcript_prefix(maps.certificate_digest(), reset_identity, &transcript, 5),
        );
    }

    #[test]
    fn live_cross_epoch_prefix_accepts_only_the_compiled_rank_two_relation() {
        let (contract, maps) = selected();
        let inputs = contract.verifier_inputs();
        let messages = [
            selected_adversarial_message(&inputs, 0),
            selected_adversarial_message(&inputs, 1),
        ];
        let first = CompactChallengeField::from_u64(17);
        let second = CompactChallengeField::from_u64(29);
        let auxiliary = CompactChallengeField::from_u64(41);

        verify_selected_compact_cross_epoch_masking_prefix(
            contract.verifier_inputs(),
            &maps,
            [0x21; 32],
            &[0x31],
            &[0x41],
            &[0x51],
            &messages,
            [first, second, first - second],
            auxiliary,
        )
        .expect("the real cross-epoch disclosure belongs to the compiled conditional image");
        assert_eq!(
            verify_selected_compact_cross_epoch_masking_prefix(
                contract.verifier_inputs(),
                &maps,
                [0x21; 32],
                &[0x31],
                &[0x41],
                &[0x51],
                &messages,
                [first, second, first - second + CompactChallengeField::ONE],
                auxiliary,
            ),
            Err(CompactMaskingEntropyError::InvalidCoefficientMap),
        );
        assert_eq!(
            verify_selected_compact_cross_epoch_masking_prefix(
                contract.verifier_inputs(),
                &maps,
                [0x21; 32],
                &[0x31],
                &[0x41],
                &[0x51],
                &messages[..1],
                [first, second, first - second],
                auxiliary,
            ),
            Err(CompactMaskingEntropyError::MissingTranscriptInput),
        );
    }

    #[test]
    fn live_masking_gate_replays_first_source_queries_before_the_second_whir_batch() {
        let (contract, maps) = selected();
        let inputs = contract.verifier_inputs();
        let mut messages = vec![
            selected_adversarial_message(&inputs, 0),
            selected_adversarial_message(&inputs, 1),
        ];
        let first_cross_epoch_value = CompactChallengeField::from_u64(17);
        let second_cross_epoch_value = CompactChallengeField::from_u64(29);
        let auxiliary_target = CompactChallengeField::from_u64(41);
        let identity = verify_selected_compact_cross_epoch_masking_prefix(
            contract.verifier_inputs(),
            &maps,
            [0x61; 32],
            &[0x71],
            &[0x81],
            &[0x91],
            &messages,
            [
                first_cross_epoch_value,
                second_cross_epoch_value,
                first_cross_epoch_value - second_cross_epoch_value,
            ],
            auxiliary_target,
        )
        .expect("the initial live masking prefix mints one attempt identity");

        let mut authority =
            CompactMaskingEntropyAuthority::begin(contract.verifier_inputs(), &maps, identity)
                .expect("the selected streaming authority begins");
        for (move_ordinal, message) in messages.iter().enumerate() {
            authority
                .authorize_next_response(None)
                .expect("the response prefix is ordered");
            authority
                .ingest_verifier_message(move_ordinal as u32, message)
                .expect("the verifier prefix is ordered");
        }
        let initial_steps = authority
            .authorize_next_response(None)
            .expect("the cross-epoch response is authorized");
        assert_eq!(initial_steps.len(), 2);
        messages.push(selected_adversarial_message(&inputs, 2));
        authority
            .ingest_verifier_message(2, &messages[2])
            .expect("the initial CFW message is accepted");

        let round_count = inputs.cfw_configuration.geometry().sumcheck_round_count();
        let mut preceding_outer_outputs = vec![auxiliary_target];
        for round_index in 0..round_count {
            let steps = authority
                .authorize_next_response(None)
                .expect("the next CFW round is authorized")
                .to_vec();
            let [round_step] = steps.as_slice() else {
                panic!("one CFW masking step must own each round")
            };
            assert_eq!(round_step.conditional_rank(), 7);
            let request = authority
                .prepare_coefficient_image(round_step, &preceding_outer_outputs, None)
                .expect("the round conditional image derives");
            let independent_coordinates = (0..round_step.conditional_rank())
                .map(|coordinate_ordinal| {
                    CompactChallengeField::from_u64(
                        101 + u64::try_from(round_index).unwrap() * 16 + coordinate_ordinal,
                    )
                })
                .collect::<Vec<_>>();
            let round_polynomial: [CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH] =
                authority
                    .execute_coefficient_image(round_step, &request, &independent_coordinates)
                    .expect("the exact affine image produces one round polynomial")
                    .try_into()
                    .expect("the CFW round polynomial has eight coordinates");
            verify_selected_compact_cfw_round_masking(
                contract.verifier_inputs(),
                &maps,
                identity,
                &messages,
                &preceding_outer_outputs,
                u32::try_from(round_index).unwrap(),
                &round_polynomial,
            )
            .expect("the production gate accepts the compiler-derived round image");
            if round_index == 0 {
                let mut hostile_polynomial = round_polynomial;
                hostile_polynomial[0] += CompactChallengeField::ONE;
                assert_eq!(
                    verify_selected_compact_cfw_round_masking(
                        contract.verifier_inputs(),
                        &maps,
                        identity,
                        &messages,
                        &preceding_outer_outputs,
                        0,
                        &hostile_polynomial,
                    ),
                    Err(CompactMaskingEntropyError::InvalidCoefficientMap),
                );
            }
            preceding_outer_outputs.extend_from_slice(&round_polynomial);
            let move_index = round_index + 3;
            messages.push(selected_adversarial_message(&inputs, move_index));
            authority
                .ingest_verifier_message(
                    u32::try_from(move_index).unwrap(),
                    messages.last().unwrap(),
                )
                .expect("the next CFW challenge is accepted");
        }

        let final_steps = authority
            .authorize_next_response(None)
            .expect("the final CFW response is authorized")
            .to_vec();
        let [terminal_step, outer_step] = final_steps.as_slice() else {
            panic!("the final CFW response has terminal and outer masking views")
        };
        let terminal_request = authority
            .prepare_coefficient_image(terminal_step, &[], None)
            .expect("the terminal inner conditional image derives");
        let terminal_independent_coordinates = (0..terminal_step.conditional_rank())
            .map(|coordinate_ordinal| CompactChallengeField::from_u64(801 + coordinate_ordinal))
            .collect::<Vec<_>>();
        let final_values: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT] = authority
            .execute_coefficient_image(
                terminal_step,
                &terminal_request,
                &terminal_independent_coordinates,
            )
            .expect("the terminal inner image executes")
            .try_into()
            .expect("the terminal view has three coordinates");
        let outer_request = authority
            .prepare_cfw_final_outer_image(outer_step, &preceding_outer_outputs, &final_values)
            .expect("the verifier-translated final outer image derives");
        let outer_independent_coordinates = (0..outer_step.conditional_rank())
            .map(|coordinate_ordinal| CompactChallengeField::from_u64(701 + coordinate_ordinal))
            .collect::<Vec<_>>();
        let outer_evaluations = authority
            .execute_coefficient_image(outer_step, &outer_request, &outer_independent_coordinates)
            .expect("the final outer image executes");
        verify_selected_compact_cfw_finish_masking(
            contract.verifier_inputs(),
            &maps,
            identity,
            &messages,
            &preceding_outer_outputs,
            &outer_evaluations,
            &final_values,
        )
        .expect("the production gate accepts both final CFW images");

        let mut hostile_outer_evaluations = outer_evaluations.clone();
        hostile_outer_evaluations[0] += CompactChallengeField::ONE;
        assert_eq!(
            verify_selected_compact_cfw_finish_masking(
                contract.verifier_inputs(),
                &maps,
                identity,
                &messages,
                &preceding_outer_outputs,
                &hostile_outer_evaluations,
                &final_values,
            ),
            Err(CompactMaskingEntropyError::InvalidCoefficientMap),
        );

        let mut hostile_final_values = final_values;
        hostile_final_values[0] += CompactChallengeField::ONE;
        assert_eq!(
            verify_selected_compact_cfw_finish_masking(
                contract.verifier_inputs(),
                &maps,
                identity,
                &messages,
                &preceding_outer_outputs,
                &outer_evaluations,
                &hostile_final_values,
            ),
            Err(CompactMaskingEntropyError::InvalidCoefficientMap),
        );

        let final_cfw_message_ordinal = messages.len();
        messages.push(selected_adversarial_message(
            &inputs,
            final_cfw_message_ordinal,
        ));
        authority
            .ingest_verifier_message(
                u32::try_from(final_cfw_message_ordinal).unwrap(),
                messages.last().unwrap(),
            )
            .expect("the final CFW verifier message is accepted");

        let auxiliary_steps = authority
            .authorize_next_response(None)
            .expect("the initial WHIR auxiliary response is authorized")
            .to_vec();
        let [auxiliary_step] = auxiliary_steps.as_slice() else {
            panic!("the initial WHIR response has one auxiliary masking view")
        };
        let auxiliary_request = authority
            .prepare_coefficient_image(auxiliary_step, &[], None)
            .expect("the initial WHIR auxiliary image derives");
        let auxiliary_independent_coordinates = (0..auxiliary_step.conditional_rank())
            .map(|coordinate_ordinal| CompactChallengeField::from_u64(901 + coordinate_ordinal))
            .collect::<Vec<_>>();
        let [whir_auxiliary_target] = authority
            .execute_coefficient_image(
                auxiliary_step,
                &auxiliary_request,
                &auxiliary_independent_coordinates,
            )
            .expect("the initial WHIR auxiliary image executes")
            .try_into()
            .expect("the initial WHIR auxiliary view has one coordinate");
        let [pre_challenge_epoch, _main_epoch] = inputs.whir_epochs else {
            panic!("the selected compact contract has both WHIR epochs")
        };
        verify_selected_compact_whir_sumcheck_auxiliary_masking(
            contract.verifier_inputs(),
            &maps,
            identity,
            &messages,
            None,
            CompactWhirSumcheckBatchCoordinate::new(pre_challenge_epoch.epoch, 0),
            whir_auxiliary_target,
        )
        .expect("the production gate accepts the compiler-derived WHIR auxiliary image");
        assert_eq!(
            verify_selected_compact_whir_sumcheck_auxiliary_masking(
                contract.verifier_inputs(),
                &maps,
                identity,
                &messages,
                None,
                CompactWhirSumcheckBatchCoordinate::new(pre_challenge_epoch.epoch + 1, 0),
                whir_auxiliary_target,
            ),
            Err(CompactMaskingEntropyError::DisclosureOutOfOrder),
        );

        let combination_message_ordinal = messages.len();
        messages.push(selected_adversarial_message(
            &inputs,
            combination_message_ordinal,
        ));
        authority
            .ingest_verifier_message(
                u32::try_from(combination_message_ordinal).unwrap(),
                messages.last().unwrap(),
            )
            .expect("the initial WHIR combination message is accepted");
        let mut preceding_sumcheck_outputs = vec![whir_auxiliary_target];
        let whir_round_count = usize::try_from(pre_challenge_epoch.folding_schedule[0]).unwrap();
        for round_index in 0..whir_round_count {
            let steps = authority
                .authorize_next_response(None)
                .expect("the next initial WHIR sumcheck round is authorized")
                .to_vec();
            let [round_step] = steps.as_slice() else {
                panic!("one WHIR masking step must own each sumcheck round")
            };
            let request = authority
                .prepare_coefficient_image(round_step, &preceding_sumcheck_outputs, None)
                .expect("the WHIR round conditional image derives");
            let independent_coordinates = (0..round_step.conditional_rank())
                .map(|coordinate_ordinal| {
                    CompactChallengeField::from_u64(
                        1_001 + u64::try_from(round_index).unwrap() * 8 + coordinate_ordinal,
                    )
                })
                .collect::<Vec<_>>();
            let round_wire: [CompactChallengeField; 2] = authority
                .execute_coefficient_image(round_step, &request, &independent_coordinates)
                .expect("the exact affine image produces one WHIR round wire")
                .try_into()
                .expect("the WHIR round wire has two coordinates");
            verify_selected_compact_whir_sumcheck_round_masking(
                contract.verifier_inputs(),
                &maps,
                identity,
                &messages,
                None,
                pre_challenge_epoch.epoch,
                0,
                u32::try_from(round_index).unwrap(),
                &preceding_sumcheck_outputs,
                &round_wire,
            )
            .expect("the production gate accepts the compiler-derived WHIR round image");
            if round_index == 0 {
                assert_eq!(
                    verify_selected_compact_whir_sumcheck_round_masking(
                        contract.verifier_inputs(),
                        &maps,
                        identity,
                        &messages,
                        None,
                        pre_challenge_epoch.epoch,
                        1,
                        0,
                        &preceding_sumcheck_outputs,
                        &round_wire,
                    ),
                    Err(CompactMaskingEntropyError::DisclosureOutOfOrder),
                );
                assert_eq!(
                    verify_selected_compact_whir_sumcheck_round_masking(
                        contract.verifier_inputs(),
                        &maps,
                        identity,
                        &messages,
                        None,
                        pre_challenge_epoch.epoch,
                        0,
                        0,
                        &[],
                        &round_wire,
                    ),
                    Err(CompactMaskingEntropyError::MissingTranscriptInput),
                );
                assert_eq!(
                    verify_selected_compact_whir_sumcheck_round_masking(
                        contract.verifier_inputs(),
                        &maps,
                        identity,
                        &messages,
                        None,
                        pre_challenge_epoch.epoch,
                        0,
                        0,
                        &preceding_sumcheck_outputs,
                        &round_wire[..1],
                    ),
                    Err(CompactMaskingEntropyError::MissingTranscriptInput),
                );
            }
            preceding_sumcheck_outputs.extend_from_slice(&round_wire);
            let round_message_ordinal = messages.len();
            messages.push(selected_adversarial_message(&inputs, round_message_ordinal));
            authority
                .ingest_verifier_message(
                    u32::try_from(round_message_ordinal).unwrap(),
                    messages.last().unwrap(),
                )
                .expect("the next WHIR round challenge is accepted");
        }

        assert!(
            authority
                .authorize_next_response(None)
                .expect("the first code-switch response is authorized")
                .is_empty()
        );
        let code_switch_message_ordinal = messages.len();
        messages.push(selected_adversarial_message(
            &inputs,
            code_switch_message_ordinal,
        ));
        let source_query_steps = authority
            .ingest_verifier_message(
                u32::try_from(code_switch_message_ordinal).unwrap(),
                messages.last().unwrap(),
            )
            .expect("the first code-switch query message is accepted")
            .to_vec();
        let [source_query_step] = source_query_steps.as_slice() else {
            panic!("the first code-switch message selects one source-query view")
        };
        assert_eq!(
            source_query_step.kind(),
            CompactMaskingDisclosureKind::SourceQueries {
                epoch: pre_challenge_epoch.epoch,
                source_ordinal: 0,
            }
        );
        let source_query_request = authority
            .prepare_coefficient_image(source_query_step, &[], None)
            .expect("the first source-query conditional image derives");
        let independent_query_coordinates = (0..source_query_step.conditional_rank())
            .map(|coordinate_ordinal| CompactChallengeField::from_u64(1_101 + coordinate_ordinal))
            .collect::<Vec<_>>();
        let query_outputs = authority
            .execute_coefficient_image(
                source_query_step,
                &source_query_request,
                &independent_query_coordinates,
            )
            .expect("the query-major source image executes");
        verify_selected_compact_whir_source_query_masking(
            contract.verifier_inputs(),
            &maps,
            identity,
            &messages,
            None,
            pre_challenge_epoch.epoch,
            0,
            &query_outputs,
        )
        .expect("the live gate accepts the exact source-query conditional image");
        assert_eq!(
            verify_selected_compact_whir_source_query_masking(
                contract.verifier_inputs(),
                &maps,
                identity,
                &messages,
                None,
                pre_challenge_epoch.epoch,
                1,
                &query_outputs,
            ),
            Err(CompactMaskingEntropyError::DisclosureOutOfOrder),
        );
        assert_eq!(
            verify_selected_compact_whir_source_query_masking(
                contract.verifier_inputs(),
                &maps,
                identity,
                &messages,
                None,
                pre_challenge_epoch.epoch,
                0,
                &query_outputs[..query_outputs.len() - 1],
            ),
            Err(CompactMaskingEntropyError::DisclosureOutOfOrder),
        );
        assert_eq!(
            verify_selected_compact_whir_source_query_masking(
                contract.verifier_inputs(),
                &maps,
                identity,
                &messages[..messages.len() - 1],
                None,
                pre_challenge_epoch.epoch,
                0,
                &query_outputs,
            ),
            Err(CompactMaskingEntropyError::DisclosureOutOfOrder),
        );

        let second_auxiliary_steps = authority
            .authorize_next_response(None)
            .expect("the second WHIR auxiliary response is authorized")
            .to_vec();
        let [second_auxiliary_step] = second_auxiliary_steps.as_slice() else {
            panic!("the second WHIR response has one auxiliary masking view")
        };
        assert_eq!(
            second_auxiliary_step.kind(),
            CompactMaskingDisclosureKind::WhirSumcheckAuxiliary {
                epoch: pre_challenge_epoch.epoch,
                batch_ordinal: 1,
            }
        );
        let second_auxiliary_request = authority
            .prepare_coefficient_image(second_auxiliary_step, &[], None)
            .expect("the second WHIR auxiliary image derives");
        let second_auxiliary_independent_coordinates = (0..second_auxiliary_step
            .conditional_rank())
            .map(|coordinate_ordinal| CompactChallengeField::from_u64(1_201 + coordinate_ordinal))
            .collect::<Vec<_>>();
        let [second_whir_auxiliary_target] = authority
            .execute_coefficient_image(
                second_auxiliary_step,
                &second_auxiliary_request,
                &second_auxiliary_independent_coordinates,
            )
            .expect("the second WHIR auxiliary image executes")
            .try_into()
            .expect("the second WHIR auxiliary view has one coordinate");
        verify_selected_compact_whir_sumcheck_auxiliary_masking(
            contract.verifier_inputs(),
            &maps,
            identity,
            &messages,
            None,
            CompactWhirSumcheckBatchCoordinate::new(pre_challenge_epoch.epoch, 1),
            second_whir_auxiliary_target,
        )
        .expect("the second auxiliary gate replays the full-rank source-query disclosure");
    }

    #[test]
    fn conditional_image_prefix_binding_commits_to_carried_covector_coefficients() {
        let (contract, maps) = selected();
        let transcript =
            selected_test_transcript(&contract.verifier_inputs()).expect("selected transcript");
        let identity = CompactMaskingAttemptIdentity::new([8; 32], 0, [12; 64]);
        let mut altered = transcript.clone();
        altered.base_fresh_claims[0].coefficients[0] += CompactChallengeField::ONE;

        assert_ne!(
            hash_transcript_prefix(maps.certificate_digest(), identity, &transcript, 5),
            hash_transcript_prefix(maps.certificate_digest(), identity, &altered, 5),
        );
    }
}
