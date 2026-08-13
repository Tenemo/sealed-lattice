//! Public-only carried-covector replay for the selected role-18 responses.
//!
//! The authority is constructed only from the canonical public-input view
//! owned by the verified compact transport. It parses the same decoded
//! verifier-message prefix exposed by the simulator and recomputes the full
//! carried reduction. No proof target, assignment, witness, caller vector, or
//! caller digest participates in this coefficient authority.

use p3_field::{Field, PrimeCharacteristicRing};

use super::super::compact_cfw::{
    CompactCfwError, CompactCfwPublicMainCovectorCombination,
    CompactCfwPublicMainCovectorContinuation, CompactCfwPublicMainCovectors, CompactChallengeField,
    compact_challenge_from_production,
};
use super::super::compact_masking_simulator::CompactMaskingSemanticPrefix;
use super::super::compact_proof_contract::{
    CompactProofContractError, CompactPublicKeyVerifierInputs, CompactVerifierMoveContract,
    CompactVerifierRoleCoordinate, CompactWhirEpochContract, CompactWhirFoldContract,
};
use super::super::compact_proof_wire::CompactProofWireError;
use super::super::compact_public_key_verifier::{
    VerifiedCompactPublicInputTransport, VerifiedCompactPublicInputTransportView,
};
use super::super::compact_reed_solomon::{
    CanonicalReedSolomonError, CanonicalReedSolomonGeometry,
    canonical_reed_solomon_evaluation_points,
};
use super::super::field::{ProofBaseFieldElement, ProofChallengeExtensionElement};
use super::super::fixed_uniform_verifier_message::DecodedFixedUniformVerifierMessage;
use super::super::prover::CommonProofProverError;
use super::super::relation_plan::{
    CompactStructuredWitnessCovectorAccumulator, CompactStructuredWitnessCovectorAccumulatorPoll,
    StructuredTransposeValueSource,
};

const PRE_CHALLENGE_ROLE18_COEFFICIENT_COUNT: usize = 1_292;
const MAIN_ROLE18_COEFFICIENT_COUNT: usize = 1_755;
const WHIR_BATCH_COUNT: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompactFactorOnePublicCovectorError {
    ArithmeticOverflow,
    InvalidContract,
    InvalidPublicInput,
    InvalidVerifierPrefix,
    InvalidCovector,
    Cfw(CompactCfwError),
    Transpose(CommonProofProverError),
    ReedSolomon(CanonicalReedSolomonError),
}

impl From<CompactCfwError> for CompactFactorOnePublicCovectorError {
    fn from(error: CompactCfwError) -> Self {
        Self::Cfw(error)
    }
}

impl From<CommonProofProverError> for CompactFactorOnePublicCovectorError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Transpose(error)
    }
}

impl From<CanonicalReedSolomonError> for CompactFactorOnePublicCovectorError {
    fn from(error: CanonicalReedSolomonError) -> Self {
        Self::ReedSolomon(error)
    }
}

impl From<CompactProofWireError> for CompactFactorOnePublicCovectorError {
    fn from(_: CompactProofWireError) -> Self {
        Self::InvalidPublicInput
    }
}

impl From<CompactProofContractError> for CompactFactorOnePublicCovectorError {
    fn from(_: CompactProofContractError) -> Self {
        Self::InvalidContract
    }
}

/// Opaque deterministic coefficient vector. Only this module can construct
/// it, and only the masking entropy owner can borrow its coefficients.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CompactFactorOneCarriedCovector {
    pending: Option<CompactFactorOneBoundCarriedCovector>,
}

impl CompactFactorOneCarriedCovector {
    pub(crate) fn epoch(&self) -> Option<u8> {
        self.pending.as_ref().map(|pending| pending.prefix.epoch())
    }

    pub(in crate::bgv::proof_suite) fn coefficients(&self) -> Option<&[CompactChallengeField]> {
        self.pending
            .as_ref()
            .map(|pending| pending.coefficients.as_slice())
    }

    pub(in crate::bgv::proof_suite) fn authorizes(
        &self,
        prefix: &CompactMaskingSemanticPrefix,
        public_input_binding: [u8; 64],
    ) -> bool {
        self.pending.as_ref().is_some_and(|pending| {
            pending.public_input_binding == public_input_binding
                && pending.prefix.attempt_identity() == prefix.attempt_identity()
                && pending.prefix.verifier_move_ordinal() == prefix.verifier_move_ordinal()
                && pending.prefix.epoch() == prefix.epoch()
                && pending.prefix.contract_source_hash() == prefix.contract_source_hash()
                && pending.prefix.canonical_exposed_move_prefix()
                    == prefix.canonical_exposed_move_prefix()
                && pending.prefix.completed_messages() == prefix.completed_messages()
        })
    }

    pub(in crate::bgv::proof_suite) fn consume(
        &mut self,
        prefix: &CompactMaskingSemanticPrefix,
        public_input_binding: [u8; 64],
    ) -> Result<(), CompactFactorOnePublicCovectorError> {
        if !self.authorizes(prefix, public_input_binding) {
            return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
        }
        self.pending = None;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CompactFactorOneBoundCarriedCovector {
    prefix: CompactMaskingSemanticPrefix,
    public_input_binding: [u8; 64],
    coefficients: Vec<CompactChallengeField>,
}

/// Public-only authority inseparably borrowing the decoded canonical input
/// ranges owned by one verified transport.
pub(crate) struct CompactFactorOnePublicCovectorAuthority<'transport> {
    verifier_inputs: CompactPublicKeyVerifierInputs<'transport>,
    public_input: VerifiedCompactPublicInputTransportView<'transport>,
    contract_source_hash: [u8; 64],
}

impl<'transport> CompactFactorOnePublicCovectorAuthority<'transport> {
    pub(crate) fn from_verified_public_input(
        public_input: &'transport VerifiedCompactPublicInputTransport,
    ) -> Result<Self, CompactFactorOnePublicCovectorError> {
        let verifier_inputs = public_input.verifier_inputs();
        let public_input = public_input.view();
        let contract_source_hash = verifier_inputs.canonical_source_hash()?.into_bytes();
        let explicit_public_input_element_count = u64::try_from(public_input.field_element_count())
            .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?;
        if explicit_public_input_element_count
            .checked_add(1)
            .ok_or(CompactFactorOnePublicCovectorError::ArithmeticOverflow)?
            > verifier_inputs.relation.padded_public_input_element_count()
        {
            return Err(CompactFactorOnePublicCovectorError::InvalidPublicInput);
        }
        Ok(Self {
            verifier_inputs,
            public_input,
            contract_source_hash,
        })
    }

    pub(crate) const fn contract_source_hash(&self) -> [u8; 64] {
        self.contract_source_hash
    }

    pub(crate) const fn public_input_binding(&self) -> [u8; 64] {
        self.public_input.binding()
    }

    pub(crate) fn begin_prefix_derivation<'authority>(
        &'authority self,
        prefix: CompactMaskingSemanticPrefix,
    ) -> Result<
        CompactFactorOnePublicCovectorDerivation<'authority, 'transport>,
        CompactFactorOnePublicCovectorError,
    > {
        if prefix.contract_source_hash() != self.contract_source_hash {
            return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
        }
        let epoch = prefix.epoch();
        if self
            .verifier_inputs
            .verifier_moves
            .get(prefix.completed_messages().len())
            .is_none_or(|next_move| next_move.ordinal != prefix.verifier_move_ordinal())
        {
            return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
        }
        let parsed =
            ParsedVerifierPrefix::parse(&self.verifier_inputs, prefix.completed_messages(), epoch)?;
        if epoch == 1 {
            let initial = pre_challenge_initial_covectors(&self.verifier_inputs, &parsed)?;
            let output = reduce_whir_epoch(
                &self.verifier_inputs,
                parsed,
                initial,
                0,
                prefix,
                self.public_input.binding(),
            )?;
            return Ok(CompactFactorOnePublicCovectorDerivation {
                state: CompactFactorOnePublicCovectorDerivationState::Complete(Some(output)),
            });
        }
        if epoch != 2 {
            return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
        }
        let geometry = self.verifier_inputs.cfw_configuration.geometry();
        let first_fold_challenges = parsed
            .whir_batches
            .first()
            .ok_or(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix)?
            .folding_challenges
            .as_slice();
        let projected_source_element_count = geometry
            .witness_length()
            .checked_shr(
                u32::try_from(first_fold_challenges.len())
                    .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?,
            )
            .ok_or(CompactFactorOnePublicCovectorError::ArithmeticOverflow)?;
        if u64::try_from(projected_source_element_count)
            .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?
            != self.verifier_inputs.relation.ring_degree()
        {
            return Err(CompactFactorOnePublicCovectorError::InvalidContract);
        }
        let combination =
            CompactCfwPublicMainCovectorCombination::from_public_challenges_after_first_whir_fold(
                geometry,
                &parsed.cross_epoch_point,
                usize::try_from(
                    self.verifier_inputs
                        .cfw_configuration
                        .cross_epoch()
                        .copied_element_count,
                )
                .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?,
                &parsed.cfw_round_challenges,
                parsed
                    .cfw_joint_challenge
                    .ok_or(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix)?,
                parsed.opening_batching_challenge,
                first_fold_challenges,
            )?;
        let (continuation, destination) = combination.into_parts();
        let transpose_source = CompactFactorOnePublicTransposeSource {
            public_input: self.public_input,
            padded_public_input_element_count: self
                .verifier_inputs
                .relation
                .padded_public_input_element_count(),
            lookup_challenge: parsed.lookup_challenge,
        };
        let accumulator =
            CompactStructuredWitnessCovectorAccumulator::from_projected_public_relation(
                transpose_source,
                self.verifier_inputs.relation,
                continuation.row_point(),
                continuation.matrix_role_weights(),
                destination,
                first_fold_challenges,
            )?;
        Ok(CompactFactorOnePublicCovectorDerivation {
            state: CompactFactorOnePublicCovectorDerivationState::MainTranspose {
                authority: self,
                prefix: Some(prefix),
                parsed: Some(parsed),
                accumulator,
                continuation: Some(continuation),
            },
        })
    }
}

pub(crate) enum CompactFactorOnePublicCovectorPoll {
    WorkCompleted { completed_element_count: u64 },
    Complete(CompactFactorOneCarriedCovector),
}

pub(crate) struct CompactFactorOnePublicCovectorDerivation<'authority, 'transport> {
    state: CompactFactorOnePublicCovectorDerivationState<'authority, 'transport>,
}

enum CompactFactorOnePublicCovectorDerivationState<'authority, 'transport> {
    Complete(Option<CompactFactorOneCarriedCovector>),
    MainTranspose {
        authority: &'authority CompactFactorOnePublicCovectorAuthority<'transport>,
        prefix: Option<CompactMaskingSemanticPrefix>,
        parsed: Option<ParsedVerifierPrefix>,
        accumulator: CompactStructuredWitnessCovectorAccumulator<
            CompactFactorOnePublicTransposeSource<'transport>,
        >,
        continuation: Option<CompactCfwPublicMainCovectorContinuation>,
    },
}

struct CompactFactorOnePublicTransposeSource<'transport> {
    public_input: VerifiedCompactPublicInputTransportView<'transport>,
    padded_public_input_element_count: u64,
    lookup_challenge: ProofChallengeExtensionElement,
}

impl StructuredTransposeValueSource for CompactFactorOnePublicTransposeSource<'_> {
    fn lookup_challenge(&self) -> ProofChallengeExtensionElement {
        self.lookup_challenge
    }

    fn public_input_base_value(
        &self,
        element_ordinal: u64,
    ) -> Result<ProofBaseFieldElement, CommonProofProverError> {
        if element_ordinal >= self.padded_public_input_element_count {
            return Err(CommonProofProverError::InvalidInput);
        }
        if element_ordinal == 0 {
            return Ok(ProofBaseFieldElement::ONE);
        }
        let explicit_ordinal = usize::try_from(element_ordinal - 1)
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        if explicit_ordinal < self.public_input.field_element_count() {
            return self
                .public_input
                .field_element(explicit_ordinal)
                .map_err(|_| CommonProofProverError::CanonicalEncoding);
        }
        Ok(ProofBaseFieldElement::ZERO)
    }
}

impl CompactFactorOnePublicCovectorDerivation<'_, '_> {
    pub(crate) fn advance(
        &mut self,
        maximum_element_count: u64,
    ) -> Result<CompactFactorOnePublicCovectorPoll, CompactFactorOnePublicCovectorError> {
        match &mut self.state {
            CompactFactorOnePublicCovectorDerivationState::Complete(output) => output
                .take()
                .map(CompactFactorOnePublicCovectorPoll::Complete)
                .ok_or(CompactFactorOnePublicCovectorError::InvalidCovector),
            CompactFactorOnePublicCovectorDerivationState::MainTranspose {
                authority,
                prefix,
                parsed,
                accumulator,
                continuation,
            } => match accumulator.advance(maximum_element_count)? {
                CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                    completed_work_unit_count,
                    ..
                } => Ok(CompactFactorOnePublicCovectorPoll::WorkCompleted {
                    completed_element_count: completed_work_unit_count,
                }),
                CompactStructuredWitnessCovectorAccumulatorPoll::Complete(source_covector) => {
                    let public_main = continuation
                        .take()
                        .ok_or(CompactFactorOnePublicCovectorError::InvalidCovector)?
                        .finish_after_projected_matrix_accumulation(source_covector)?;
                    let parsed = parsed
                        .take()
                        .ok_or(CompactFactorOnePublicCovectorError::InvalidCovector)?;
                    let initial = main_initial_covectors(public_main);
                    let prefix = prefix
                        .take()
                        .ok_or(CompactFactorOnePublicCovectorError::InvalidCovector)?;
                    let output = reduce_whir_epoch(
                        &authority.verifier_inputs,
                        parsed,
                        initial,
                        1,
                        prefix,
                        authority.public_input.binding(),
                    )?;
                    Ok(CompactFactorOnePublicCovectorPoll::Complete(output))
                }
            },
        }
    }
}

#[derive(Clone)]
struct ParsedVerifierPrefix {
    epoch: u8,
    lookup_challenge: ProofChallengeExtensionElement,
    cross_epoch_point: Vec<CompactChallengeField>,
    cfw_round_challenges: Vec<CompactChallengeField>,
    cfw_joint_challenge: Option<CompactChallengeField>,
    opening_batching_challenge: CompactChallengeField,
    whir_batches: Vec<ParsedWhirBatch>,
}

#[derive(Clone)]
struct ParsedWhirBatch {
    combining_challenge: CompactChallengeField,
    folding_challenges: Vec<CompactChallengeField>,
    code_switch: Option<ParsedCodeSwitch>,
}

#[derive(Clone)]
struct ParsedCodeSwitch {
    combination_challenge: CompactChallengeField,
    query_positions: Vec<usize>,
}

impl ParsedVerifierPrefix {
    fn parse(
        inputs: &CompactPublicKeyVerifierInputs<'_>,
        messages: &[DecodedFixedUniformVerifierMessage],
        epoch: u8,
    ) -> Result<Self, CompactFactorOnePublicCovectorError> {
        if messages.is_empty() || messages.len() >= inputs.verifier_moves.len() {
            return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
        }
        for (contract, message) in inputs.verifier_moves.iter().zip(messages) {
            validate_decoded_message(contract, message)?;
        }
        let next_move = inputs
            .verifier_moves
            .get(messages.len())
            .ok_or(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix)?;
        if !next_move
            .role_coordinates
            .iter()
            .any(|role| role.role_tag == 10 && role.epoch == epoch)
        {
            return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
        }

        let lookup = unique_role_extension(inputs, messages, 1, 0, 0, 0)?;
        let [lookup_challenge] = lookup.as_slice() else {
            return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
        };
        let cross_epoch_point = unique_role_extension(inputs, messages, 2, 0, 0, 0)?;
        let expected_cross_count = usize::try_from(
            inputs
                .cfw_configuration
                .cross_epoch()
                .point_coordinate_count,
        )
        .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?;
        if cross_epoch_point.len() != expected_cross_count {
            return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
        }
        let mut cfw_round_challenges = Vec::new();
        for round_ordinal in 0..inputs.cfw_configuration.geometry().sumcheck_round_count() {
            let values = unique_role_extension(
                inputs,
                messages,
                4,
                0,
                0,
                u32::try_from(round_ordinal)
                    .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?,
            )?;
            let [challenge] = values.as_slice() else {
                return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
            };
            cfw_round_challenges.push(*challenge);
        }
        let cfw_joint_challenge = if epoch == 2 {
            let values = unique_role_extension(inputs, messages, 5, 0, 0, 0)?;
            let [challenge] = values.as_slice() else {
                return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
            };
            Some(*challenge)
        } else {
            None
        };
        let opening = unique_role_extension(inputs, messages, 6, epoch, 0, 0)?;
        let [opening_batching_challenge] = opening.as_slice() else {
            return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
        };
        let epoch_contract = inputs
            .whir_epochs
            .iter()
            .find(|candidate| candidate.epoch == epoch)
            .ok_or(CompactFactorOnePublicCovectorError::InvalidContract)?;
        let folds = epoch_folds(inputs, epoch)?;
        let mut whir_batches = Vec::with_capacity(WHIR_BATCH_COUNT);
        for batch_ordinal in 0..WHIR_BATCH_COUNT {
            let batch = u8::try_from(batch_ordinal)
                .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?;
            let combining = unique_role_extension(inputs, messages, 7, epoch, batch, 0)?;
            let [combining_challenge] = combining.as_slice() else {
                return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
            };
            let fold_count = usize::try_from(epoch_contract.folding_schedule[batch_ordinal])
                .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?;
            let mut folding_challenges = Vec::with_capacity(fold_count);
            for round_ordinal in 0..fold_count {
                let values = unique_role_extension(
                    inputs,
                    messages,
                    8,
                    epoch,
                    batch,
                    u32::try_from(round_ordinal)
                        .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?,
                )?;
                let [challenge] = values.as_slice() else {
                    return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
                };
                folding_challenges.push(compact_challenge_from_production(*challenge));
            }
            let code_switch = if batch_ordinal + 1 < WHIR_BATCH_COUNT {
                Some(unique_code_switch(
                    inputs,
                    messages,
                    epoch,
                    u32::try_from(batch_ordinal)
                        .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?,
                    folds[batch_ordinal],
                )?)
            } else {
                None
            };
            whir_batches.push(ParsedWhirBatch {
                combining_challenge: compact_challenge_from_production(*combining_challenge),
                folding_challenges,
                code_switch,
            });
        }
        Ok(Self {
            epoch,
            lookup_challenge: *lookup_challenge,
            cross_epoch_point: compact_vector(cross_epoch_point),
            cfw_round_challenges: compact_vector(cfw_round_challenges),
            cfw_joint_challenge: cfw_joint_challenge.map(compact_challenge_from_production),
            opening_batching_challenge: compact_challenge_from_production(
                *opening_batching_challenge,
            ),
            whir_batches,
        })
    }
}

#[derive(Clone)]
struct PublicCovectorState {
    source: Vec<CompactChallengeField>,
    mask_groups: Vec<Vec<CompactChallengeField>>,
}

fn pre_challenge_initial_covectors(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    parsed: &ParsedVerifierPrefix,
) -> Result<PublicCovectorState, CompactFactorOnePublicCovectorError> {
    let epoch = epoch_contract(inputs, 1)?;
    let source_length = 1_usize
        .checked_shl(epoch.polynomial_variable_count)
        .ok_or(CompactFactorOnePublicCovectorError::ArithmeticOverflow)?;
    let source = multilinear_equality_covector(&parsed.cross_epoch_point, source_length)?;
    Ok(PublicCovectorState {
        source,
        mask_groups: vec![vec![
            CompactChallengeField::ONE,
            CompactChallengeField::ZERO,
        ]],
    })
}

fn main_initial_covectors(public_main: CompactCfwPublicMainCovectors) -> PublicCovectorState {
    PublicCovectorState {
        source: public_main.source,
        mask_groups: vec![
            public_main.inner_masks.into_iter().flatten().collect(),
            public_main.outer_masks.into_iter().flatten().collect(),
            public_main
                .cross_epoch_masks
                .into_iter()
                .flatten()
                .collect(),
        ],
    }
}

fn reduce_whir_epoch(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    parsed: ParsedVerifierPrefix,
    mut state: PublicCovectorState,
    already_folded_batch_count: usize,
    prefix: CompactMaskingSemanticPrefix,
    public_input_binding: [u8; 64],
) -> Result<CompactFactorOneCarriedCovector, CompactFactorOnePublicCovectorError> {
    let epoch = epoch_contract(inputs, parsed.epoch)?;
    let folds = epoch_folds(inputs, parsed.epoch)?;
    if parsed.whir_batches.len() != WHIR_BATCH_COUNT {
        return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
    }
    if already_folded_batch_count > parsed.whir_batches.len() {
        return Err(CompactFactorOnePublicCovectorError::InvalidCovector);
    }
    for (batch_ordinal, batch) in parsed.whir_batches.iter().enumerate() {
        let fold_count = usize::try_from(epoch.folding_schedule[batch_ordinal])
            .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?;
        if batch.folding_challenges.len() != fold_count {
            return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
        }
        if batch_ordinal >= already_folded_batch_count {
            state.source = fold_flattened_covector(
                &state.source,
                1_usize
                    .checked_shl(
                        u32::try_from(fold_count)
                            .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?,
                    )
                    .ok_or(CompactFactorOnePublicCovectorError::ArithmeticOverflow)?,
                &batch.folding_challenges,
            )?;
        }
        scale_in_place(&mut state.source, batch.combining_challenge);
        let mask_scale = batch.combining_challenge * compact_power_of_two(fold_count).inverse();
        for group in &mut state.mask_groups {
            scale_in_place(group, mask_scale);
        }
        let mut sumcheck_group = Vec::with_capacity(
            fold_count
                .checked_mul(3)
                .ok_or(CompactFactorOnePublicCovectorError::ArithmeticOverflow)?,
        );
        for &challenge in &batch.folding_challenges {
            sumcheck_group.extend(compact_powers(challenge, 3));
        }
        state.mask_groups.push(sumcheck_group);

        match (&batch.code_switch, folds.get(batch_ordinal + 1)) {
            (Some(code_switch), Some(output_fold)) => {
                apply_code_switch(&mut state, folds[batch_ordinal], *output_fold, code_switch)?
            }
            (None, None) => {}
            _ => return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix),
        }
    }
    let expected_groups = epoch
        .external_mask_groups
        .iter()
        .chain(&epoch.internal_mask_groups)
        .collect::<Vec<_>>();
    if state.source.len()
        != 1_usize
            .checked_shl(epoch.final_variable_count)
            .ok_or(CompactFactorOnePublicCovectorError::ArithmeticOverflow)?
        || state.mask_groups.len() != expected_groups.len()
        || state
            .mask_groups
            .iter()
            .zip(expected_groups)
            .any(|(actual, expected)| {
                u64::try_from(actual.len()).ok()
                    != expected.width.checked_mul(expected.message_length)
            })
    {
        return Err(CompactFactorOnePublicCovectorError::InvalidCovector);
    }
    let coefficient_count = state
        .mask_groups
        .iter()
        .try_fold(state.source.len(), |count, group| {
            count.checked_add(group.len())
        })
        .ok_or(CompactFactorOnePublicCovectorError::ArithmeticOverflow)?;
    let expected_count = match parsed.epoch {
        1 => PRE_CHALLENGE_ROLE18_COEFFICIENT_COUNT,
        2 => MAIN_ROLE18_COEFFICIENT_COUNT,
        _ => return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix),
    };
    if coefficient_count != expected_count {
        return Err(CompactFactorOnePublicCovectorError::InvalidCovector);
    }
    let mut coefficients = state.source;
    for group in state.mask_groups {
        coefficients.extend(group);
    }
    Ok(CompactFactorOneCarriedCovector {
        pending: Some(CompactFactorOneBoundCarriedCovector {
            prefix,
            public_input_binding,
            coefficients,
        }),
    })
}

fn apply_code_switch(
    state: &mut PublicCovectorState,
    input_fold: CompactWhirFoldContract,
    output_fold: CompactWhirFoldContract,
    code_switch: &ParsedCodeSwitch,
) -> Result<(), CompactFactorOnePublicCovectorError> {
    let logical_message_length = state.source.len();
    if u64::try_from(logical_message_length).ok() != Some(input_fold.message_length) {
        return Err(CompactFactorOnePublicCovectorError::InvalidContract);
    }
    let geometry = CanonicalReedSolomonGeometry::new(
        logical_message_length,
        usize::try_from(input_fold.hiding_randomness_length)
            .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?,
        usize::try_from(input_fold.block_length)
            .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?,
        1,
    )?;
    let evaluation_points = canonical_reed_solomon_evaluation_points(geometry)?;
    let switch_message_length = usize::try_from(input_fold.hiding_randomness_length)
        .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?;
    if output_fold
        .message_length
        .checked_mul(output_fold.oracle_width)
        .and_then(|value| usize::try_from(value).ok())
        != Some(logical_message_length)
    {
        return Err(CompactFactorOnePublicCovectorError::InvalidContract);
    }
    let mut switch_covector = vec![CompactChallengeField::ZERO; switch_message_length];
    let mut combination_coefficient = code_switch.combination_challenge;
    for &position in &code_switch.query_positions {
        let point = compact_challenge_from_production(
            *evaluation_points
                .get(position)
                .ok_or(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix)?,
        );
        let mut power = CompactChallengeField::ONE;
        for coefficient in &mut state.source {
            *coefficient += combination_coefficient * power;
            power *= point;
        }
        for coefficient in &mut switch_covector {
            *coefficient += combination_coefficient * power;
            power *= point;
        }
        combination_coefficient *= code_switch.combination_challenge;
    }
    state.mask_groups.push(switch_covector);
    Ok(())
}

fn multilinear_equality_covector(
    point: &[CompactChallengeField],
    expected_length: usize,
) -> Result<Vec<CompactChallengeField>, CompactFactorOnePublicCovectorError> {
    let mut weights = vec![CompactChallengeField::ONE];
    for &coordinate in point {
        let mut next = Vec::with_capacity(
            weights
                .len()
                .checked_mul(2)
                .ok_or(CompactFactorOnePublicCovectorError::ArithmeticOverflow)?,
        );
        for &weight in &weights {
            next.push(weight * (CompactChallengeField::ONE - coordinate));
            next.push(weight * coordinate);
        }
        weights = next;
    }
    if weights.len() != expected_length {
        return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
    }
    Ok(weights)
}

fn fold_flattened_covector(
    flattened: &[CompactChallengeField],
    width: usize,
    challenges: &[CompactChallengeField],
) -> Result<Vec<CompactChallengeField>, CompactFactorOnePublicCovectorError> {
    if width == 0 || flattened.is_empty() || !flattened.len().is_multiple_of(width) {
        return Err(CompactFactorOnePublicCovectorError::InvalidCovector);
    }
    let column_length = flattened.len() / width;
    let mut columns = flattened
        .chunks_exact(column_length)
        .map(<[CompactChallengeField]>::to_vec)
        .collect::<Vec<_>>();
    for &challenge in challenges {
        if columns.len() < 2 || !columns.len().is_multiple_of(2) {
            return Err(CompactFactorOnePublicCovectorError::InvalidCovector);
        }
        let half = columns.len() / 2;
        let one_minus = CompactChallengeField::ONE - challenge;
        columns = (0..half)
            .map(|ordinal| {
                columns[ordinal]
                    .iter()
                    .zip(&columns[half + ordinal])
                    .map(|(&zero, &one)| one_minus * zero + challenge * one)
                    .collect()
            })
            .collect();
    }
    Ok(columns.into_iter().flatten().collect())
}

fn compact_powers(value: CompactChallengeField, count: usize) -> Vec<CompactChallengeField> {
    let mut power = CompactChallengeField::ONE;
    (0..count)
        .map(|_| {
            let current = power;
            power *= value;
            current
        })
        .collect()
}

fn compact_power_of_two(exponent: usize) -> CompactChallengeField {
    (0..exponent).fold(CompactChallengeField::ONE, |value, _| value + value)
}

fn scale_in_place(values: &mut [CompactChallengeField], scale: CompactChallengeField) {
    for value in values {
        *value *= scale;
    }
}

fn compact_vector(values: Vec<ProofChallengeExtensionElement>) -> Vec<CompactChallengeField> {
    values
        .into_iter()
        .map(compact_challenge_from_production)
        .collect()
}

fn validate_decoded_message(
    contract: &CompactVerifierMoveContract,
    message: &DecodedFixedUniformVerifierMessage,
) -> Result<(), CompactFactorOnePublicCovectorError> {
    if u64::try_from(message.extension_elements().len()).ok()
        != Some(contract.message_geometry.extension_output_count())
        || u64::try_from(message.base_field_elements().len()).ok()
            != Some(contract.message_geometry.base_field_output_count())
        || message.distinct_query_groups().len()
            != contract.message_geometry.distinct_query_groups().len()
        || message
            .distinct_query_groups()
            .iter()
            .zip(contract.message_geometry.distinct_query_groups())
            .any(|(actual, geometry)| {
                u64::try_from(actual.len()).ok() != Some(geometry.query_count())
                    || actual
                        .iter()
                        .any(|position| *position >= geometry.domain_cardinality())
                    || actual.windows(2).any(|pair| pair[0] >= pair[1])
            })
    {
        return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
    }
    Ok(())
}

fn unique_role_extension(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    messages: &[DecodedFixedUniformVerifierMessage],
    role_tag: u8,
    epoch: u8,
    batch_ordinal: u8,
    round_ordinal: u32,
) -> Result<Vec<ProofChallengeExtensionElement>, CompactFactorOnePublicCovectorError> {
    let mut found = None;
    for (contract, message) in inputs.verifier_moves.iter().zip(messages) {
        for role in &contract.role_coordinates {
            if (
                role.role_tag,
                role.epoch,
                role.batch_ordinal,
                role.round_ordinal,
            ) == (role_tag, epoch, batch_ordinal, round_ordinal)
            {
                if found.is_some() {
                    return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
                }
                found = Some(role_extension_elements_for_coordinate(message, role)?);
            }
        }
    }
    found.ok_or(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix)
}

fn role_extension_elements_for_coordinate(
    message: &DecodedFixedUniformVerifierMessage,
    role: &CompactVerifierRoleCoordinate,
) -> Result<Vec<ProofChallengeExtensionElement>, CompactFactorOnePublicCovectorError> {
    let start = usize::try_from(role.extension_output_start)
        .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?;
    let end = usize::try_from(role.extension_output_end)
        .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?;
    message
        .extension_elements()
        .get(start..end)
        .map(<[ProofChallengeExtensionElement]>::to_vec)
        .ok_or(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix)
}

fn unique_code_switch(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    messages: &[DecodedFixedUniformVerifierMessage],
    epoch: u8,
    round_ordinal: u32,
    fold: CompactWhirFoldContract,
) -> Result<ParsedCodeSwitch, CompactFactorOnePublicCovectorError> {
    let mut found = None;
    for (contract, message) in inputs.verifier_moves.iter().zip(messages) {
        for role in &contract.role_coordinates {
            if (role.role_tag, role.epoch, role.round_ordinal) == (9, epoch, round_ordinal) {
                if found.is_some() {
                    return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
                }
                let extension = role_extension_elements_for_coordinate(message, role)?;
                let [combination_challenge] = extension.as_slice() else {
                    return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
                };
                let query_start = usize::try_from(role.distinct_query_group_start)
                    .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?;
                let query_end = usize::try_from(role.distinct_query_group_end)
                    .map_err(|_| CompactFactorOnePublicCovectorError::ArithmeticOverflow)?;
                let [query_group] = message
                    .distinct_query_groups()
                    .get(query_start..query_end)
                    .ok_or(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix)?
                else {
                    return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
                };
                if u64::try_from(query_group.len()).ok() != Some(fold.query_count)
                    || query_group
                        .iter()
                        .any(|position| *position >= fold.block_length)
                {
                    return Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix);
                }
                found = Some(ParsedCodeSwitch {
                    combination_challenge: compact_challenge_from_production(
                        *combination_challenge,
                    ),
                    query_positions: query_group
                        .iter()
                        .copied()
                        .map(|position| {
                            usize::try_from(position).map_err(|_| {
                                CompactFactorOnePublicCovectorError::ArithmeticOverflow
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                });
            }
        }
    }
    found.ok_or(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix)
}

fn epoch_contract<'a>(
    inputs: &'a CompactPublicKeyVerifierInputs<'_>,
    epoch: u8,
) -> Result<&'a CompactWhirEpochContract, CompactFactorOnePublicCovectorError> {
    inputs
        .whir_epochs
        .iter()
        .find(|candidate| candidate.epoch == epoch)
        .ok_or(CompactFactorOnePublicCovectorError::InvalidContract)
}

fn epoch_folds<'a>(
    inputs: &'a CompactPublicKeyVerifierInputs<'_>,
    epoch: u8,
) -> Result<&'a [CompactWhirFoldContract; WHIR_BATCH_COUNT], CompactFactorOnePublicCovectorError> {
    let start = inputs
        .whir_folds
        .iter()
        .position(|fold| fold.epoch == epoch)
        .ok_or(CompactFactorOnePublicCovectorError::InvalidContract)?;
    let folds: &[CompactWhirFoldContract; WHIR_BATCH_COUNT] = inputs
        .whir_folds
        .get(start..start + WHIR_BATCH_COUNT)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(CompactFactorOnePublicCovectorError::InvalidContract)?;
    if folds.iter().enumerate().any(|(batch_ordinal, fold)| {
        fold.epoch != epoch || usize::from(fold.batch_ordinal) != batch_ordinal
    }) {
        return Err(CompactFactorOnePublicCovectorError::InvalidContract);
    }
    Ok(folds)
}
