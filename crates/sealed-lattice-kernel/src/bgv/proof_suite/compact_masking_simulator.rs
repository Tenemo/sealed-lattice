//! Adaptive Real/Ideal masking games for the selected compact proof chronology.
//!
//! This security-game owner exposes only ideal-uniform conditioned disclosures.
//! The coefficient-map owner fixes every disclosed coordinate and construction-
//! commitment embedding; the streaming entropy owner authorizes disclosure rank
//! against the verifier messages actually chosen so far. Concrete KMAC coins,
//! A terminal fresh-attempt trace derives the pathwise Real-game fiber law and
//! checks it against the Ideal oracle's independently consumed coordinates.
//! Salted-Merkle roots, emitted bytes, and EPRO programming are separate games.

use super::compact_cfw::{COMPACT_CFW_MATRIX_COUNT, CompactChallengeField};
use super::compact_masking_coefficient_maps::{
    CompactCommitmentQuerySource, CompactConstructionCommitmentEmbedding,
    CompactConstructionCommitmentOwnership, CompactMaskingCoefficientMapCertificate,
};
use super::compact_masking_entropy::{
    CompactBaseFreshClaimCoefficients, CompactMaskingDisclosureImage, CompactMaskingDisclosureKind,
    CompactMaskingEntropyAuthority, CompactMaskingEntropyCertificate, CompactMaskingEntropyError,
    CompactMaskingEntropyStep,
};
use super::compact_masking_prefix::{CompactMaskingAttemptIdentity, CompactMaskingSemanticPrefix};
use super::compact_masking_public_covector::{
    CompactFactorOneCarriedCovector, CompactFactorOnePublicCovectorAuthority,
    CompactFactorOnePublicCovectorDerivation, CompactFactorOnePublicCovectorError,
};
use super::compact_proof_contract::{
    CompactProofContractError, CompactPublicKeyVerifierInputs, CompactVerifierMoveContract,
};
use super::fixed_uniform_verifier_message::DecodedFixedUniformVerifierMessage;
use super::profile::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT;
use crate::foundation::Hash512;
use crate::hashing::hash_framed_parts_512;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use tiny_keccak::{Hasher, Shake};

const IDEAL_PREFIX_BINDING_DOMAIN: &str = "sealed-lattice/proof/compact-adaptive-masking-prefix/v1";
const IDEAL_PRIVATE_COORDINATE_DOMAIN: &[u8] =
    b"sealed-lattice/proof/compact-adaptive-masking-private-coordinate/v1";
const IDEAL_COMMITMENT_DOMAIN: &[u8] =
    b"sealed-lattice/proof/compact-adaptive-masking-commitment/v1";
const CONSTRUCTION_MASKING_THEOREM_BINDING_DOMAIN: &str =
    "sealed-lattice/proof/compact-construction-masking-theorem/v1";
pub(crate) const COMPACT_MASKING_ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;

pub(crate) type CompactMaskingAttemptIdentifier =
    [u8; COMPACT_MASKING_ATTEMPT_IDENTIFIER_BYTE_LENGTH];

/// An abstract construction commitment, not an outer BCS Merkle root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CompactConstructionCommitmentHandle([u8; Hash512::BYTE_LENGTH]);

impl CompactConstructionCommitmentHandle {
    pub(crate) const fn as_bytes(&self) -> &[u8; Hash512::BYTE_LENGTH] {
        &self.0
    }
}

/// One opaque construction-commitment handle embedded into an exact outer-response component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactConstructionCommitmentProgram {
    embedding: CompactConstructionCommitmentEmbedding,
    handle: CompactConstructionCommitmentHandle,
}

impl CompactConstructionCommitmentProgram {
    pub(crate) const fn handle(&self) -> CompactConstructionCommitmentHandle {
        self.handle
    }
}

/// One ideal-uniform block authorized by a conditional-entropy step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactIdealDisclosure {
    entropy_step: CompactMaskingEntropyStep,
    field_values: Vec<CompactChallengeField>,
    coin_coordinate_start: u64,
}

/// Ideal information exposed before a malicious verifier chooses its message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactIdealConditionedView {
    preceding_prover_response_ordinal: u32,
    disclosures: Vec<CompactIdealDisclosure>,
    new_construction_commitments: Vec<CompactConstructionCommitmentProgram>,
}

/// Complete exposed prefix supplied to an adaptive malicious verifier.
pub(crate) struct CompactAdaptiveVerifierView<'a> {
    verifier_move: &'a CompactVerifierMoveContract,
    current_conditioned_view: &'a CompactIdealConditionedView,
}

impl CompactAdaptiveVerifierView<'_> {
    pub(crate) const fn verifier_move(&self) -> &CompactVerifierMoveContract {
        self.verifier_move
    }

    pub(crate) const fn current_conditioned_view(&self) -> &CompactIdealConditionedView {
        self.current_conditioned_view
    }
}

pub(crate) trait CompactAdaptiveVerifier {
    fn choose_message(
        &mut self,
        view: CompactAdaptiveVerifierView<'_>,
    ) -> DecodedFixedUniformVerifierMessage;
}

/// One complete verifier move, including query disclosures exposed after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactIdealMaskingMoveRecord {
    base_fresh_claim: Option<CompactBaseFreshClaimCoefficients>,
    conditioned_view: CompactIdealConditionedView,
    verifier_message: DecodedFixedUniformVerifierMessage,
    post_message_disclosures: Vec<CompactIdealDisclosure>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactAttemptState {
    attempt_identifier: CompactMaskingAttemptIdentifier,
    reset_ordinal: u32,
    initial_exposed_prefix_binding: [u8; 64],
    next_coin_coordinate: u64,
    moves: Vec<CompactIdealMaskingMoveRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactRetiredCoinRange {
    identity: CompactMaskingAttemptIdentity,
    start: u64,
    end: u64,
}

impl CompactRetiredCoinRange {
    fn overlaps(self, identity: CompactMaskingAttemptIdentity, start: u64, end: u64) -> bool {
        self.identity == identity && start < self.end && self.start < end
    }
}

impl CompactAttemptState {
    const fn new(
        attempt_identifier: CompactMaskingAttemptIdentifier,
        initial_exposed_prefix_binding: [u8; 64],
    ) -> Self {
        Self {
            attempt_identifier,
            reset_ordinal: 0,
            initial_exposed_prefix_binding,
            next_coin_coordinate: 0,
            moves: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactMaskingSimulationCheckpoint {
    contract_source_hash: Hash512,
    coefficient_map_binding: [u8; 64],
    public_input_binding: Option<[u8; 64]>,
    attempt: CompactAttemptState,
    exposed_prefix_binding: [u8; 64],
    retired_coin_ranges: Vec<CompactRetiredCoinRange>,
    retired_commitment_handles: Vec<CompactConstructionCommitmentHandle>,
    ideal_oracle_binding: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompactMaskingSimulatorError {
    Contract(CompactProofContractError),
    Entropy(CompactMaskingEntropyError),
    InvalidCoefficientMap,
    SimulationNotActive,
    IdealOracleRefused,
    ArithmeticOverflow,
    ReusedCoinCoordinate,
    ReusedCommitmentHandle,
    WrongCommitmentProgression,
    WrongCommitmentEmbedding,
    InvalidVerifierMessage,
    WrongCheckpoint,
    WrongTranscript,
    Role18AuthorizationRequired,
    InvalidRole18Authorization,
    InvalidConstructionGameLaw,
    PublicCovector(CompactFactorOnePublicCovectorError),
}

impl From<CompactProofContractError> for CompactMaskingSimulatorError {
    fn from(error: CompactProofContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<CompactMaskingEntropyError> for CompactMaskingSimulatorError {
    fn from(error: CompactMaskingEntropyError) -> Self {
        Self::Entropy(error)
    }
}

impl From<CompactFactorOnePublicCovectorError> for CompactMaskingSimulatorError {
    fn from(error: CompactFactorOnePublicCovectorError) -> Self {
        Self::PublicCovector(error)
    }
}

/// The two adaptive experiments compared by the construction-level masking
/// theorem. The Real experiment starts from a canonical relation witness and
/// uniform private construction coordinates. The Ideal experiment receives no
/// witness and samples only the independently uniform coordinates authorized by
/// each conditioned affine image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactAdaptiveMaskingExperiment {
    RealCanonicalConstruction,
    WitnessFreeIdealUniform,
}

/// Deliberately closed scope of the exact statistical claim below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactConstructionMaskingClaimScope {
    SingleCanonicalProofAttempt,
    AuthenticatedReset,
    ReusedPrivateRandomness,
    MultipleProofs,
    ProofFamily,
    Ceremony,
    SharedRandomOracle,
    ExplicitlyProgrammableRandomOracle,
    QuantumRandomOracleZeroKnowledge,
    CanonicalEmittedProofBytes,
}

/// One pathwise conditional distribution in both adaptive games.
///
/// The Real count is the independently derived rank of the compiler-owned map
/// after all earlier disclosures. The Ideal count is reconstructed from the
/// actual addressed-oracle cursor consumed by the witness-free simulator. Equal
/// counts mean that both games assign probability `|F|^-rank` to every point in
/// the same conditioned affine image. The residual dimension is the logarithm
/// over the challenge field of every Real-game fiber size after that point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactMaskingConditionalGameLaw {
    step_ordinal: u32,
    verifier_move_ordinal: u32,
    output_coordinate_count: u64,
    real_uniform_coordinate_count: u64,
    ideal_uniform_coordinate_count: u64,
    cumulative_real_rank: u64,
    real_fiber_dimension_before: u64,
    real_fiber_dimension_after: u64,
}

impl CompactMaskingConditionalGameLaw {
    pub(crate) const fn probability_exponent(
        self,
        experiment: CompactAdaptiveMaskingExperiment,
    ) -> u64 {
        match experiment {
            CompactAdaptiveMaskingExperiment::RealCanonicalConstruction => {
                self.real_uniform_coordinate_count
            }
            CompactAdaptiveMaskingExperiment::WitnessFreeIdealUniform => {
                self.ideal_uniform_coordinate_count
            }
        }
    }
}

/// Exact pathwise Real/Ideal equality for the selected abstract construction.
///
/// This object is derived only from the canonical contract, compiler maps,
/// independently verified public input, streaming rank authority, and a
/// terminal witness-free simulator trace. It is neither serialized nor accepted
/// by the proof verifier. In particular it does not cover the outer salted
/// Merkle bytes, Fiat-Shamir/QROM transformation, retries with fresh randomness,
/// or composition with another proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactConstructionMaskingTheorem {
    contract_source_hash: [u8; 64],
    coefficient_map_binding: [u8; 64],
    public_input_binding: [u8; 64],
    masking_contract_binding: [u8; 64],
    disclosure_digest: [u8; 64],
    verifier_move_count: usize,
    construction_commitment_count: usize,
    exposed_output_coordinate_count: u64,
    private_coordinate_count: u64,
    joint_disclosure_rank: u64,
    residual_fiber_dimension: u64,
    shared_cross_epoch_query_overlap: u64,
    conditional_laws: Vec<CompactMaskingConditionalGameLaw>,
    exact_statistical_distance_numerator: u8,
    exact_statistical_distance_denominator: u8,
    theorem_binding: [u8; 64],
}

impl CompactConstructionMaskingTheorem {
    pub(crate) const fn applies_to(&self, scope: CompactConstructionMaskingClaimScope) -> bool {
        matches!(
            scope,
            CompactConstructionMaskingClaimScope::SingleCanonicalProofAttempt
        )
    }

    fn check(&self) -> Result<(), CompactMaskingSimulatorError> {
        if self.theorem_binding != self.recomputed_binding()?
            || self.contract_source_hash != self.coefficient_map_binding
            || self.verifier_move_count != 82
            || self.construction_commitment_count != 45
            || self.private_coordinate_count != 230_488
            || self.joint_disclosure_rank > 230_324
            || self.residual_fiber_dimension < 164
            || self
                .joint_disclosure_rank
                .checked_add(self.residual_fiber_dimension)
                != Some(self.private_coordinate_count)
            || self.conditional_laws.is_empty()
            || self.exact_statistical_distance_numerator != 0
            || self.exact_statistical_distance_denominator != 1
            || !self.applies_to(CompactConstructionMaskingClaimScope::SingleCanonicalProofAttempt)
        {
            return Err(CompactMaskingSimulatorError::InvalidConstructionGameLaw);
        }

        let mut expected_fiber_dimension = self.private_coordinate_count;
        let mut expected_cumulative_rank = 0_u64;
        let mut expected_output_coordinate_count = 0_u64;
        for (expected_step_ordinal, law) in self.conditional_laws.iter().enumerate() {
            expected_cumulative_rank = expected_cumulative_rank
                .checked_add(law.real_uniform_coordinate_count)
                .ok_or(CompactMaskingSimulatorError::ArithmeticOverflow)?;
            expected_output_coordinate_count = expected_output_coordinate_count
                .checked_add(law.output_coordinate_count)
                .ok_or(CompactMaskingSimulatorError::ArithmeticOverflow)?;
            let expected_after = expected_fiber_dimension
                .checked_sub(law.real_uniform_coordinate_count)
                .ok_or(CompactMaskingSimulatorError::InvalidConstructionGameLaw)?;
            if usize::try_from(law.step_ordinal).ok() != Some(expected_step_ordinal)
                || usize::try_from(law.verifier_move_ordinal)
                    .ok()
                    .is_none_or(|ordinal| ordinal >= self.verifier_move_count)
                || law.real_uniform_coordinate_count != law.ideal_uniform_coordinate_count
                || law.real_uniform_coordinate_count > law.output_coordinate_count
                || law.cumulative_real_rank != expected_cumulative_rank
                || law.real_fiber_dimension_before != expected_fiber_dimension
                || law.real_fiber_dimension_after != expected_after
            {
                return Err(CompactMaskingSimulatorError::InvalidConstructionGameLaw);
            }
            expected_fiber_dimension = expected_after;
        }
        if expected_cumulative_rank != self.joint_disclosure_rank
            || expected_fiber_dimension != self.residual_fiber_dimension
            || expected_output_coordinate_count != self.exposed_output_coordinate_count
        {
            return Err(CompactMaskingSimulatorError::InvalidConstructionGameLaw);
        }
        Ok(())
    }

    fn recomputed_binding(&self) -> Result<[u8; 64], CompactMaskingSimulatorError> {
        let verifier_move_count = u64::try_from(self.verifier_move_count)
            .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?;
        let construction_commitment_count = u64::try_from(self.construction_commitment_count)
            .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?;
        let mut law_bytes = Vec::with_capacity(
            self.conditional_laws
                .len()
                .checked_mul(8 * 8)
                .ok_or(CompactMaskingSimulatorError::ArithmeticOverflow)?,
        );
        for law in &self.conditional_laws {
            law_bytes.extend_from_slice(&u64::from(law.step_ordinal).to_le_bytes());
            law_bytes.extend_from_slice(&u64::from(law.verifier_move_ordinal).to_le_bytes());
            law_bytes.extend_from_slice(&law.output_coordinate_count.to_le_bytes());
            law_bytes.extend_from_slice(&law.real_uniform_coordinate_count.to_le_bytes());
            law_bytes.extend_from_slice(&law.ideal_uniform_coordinate_count.to_le_bytes());
            law_bytes.extend_from_slice(&law.cumulative_real_rank.to_le_bytes());
            law_bytes.extend_from_slice(&law.real_fiber_dimension_before.to_le_bytes());
            law_bytes.extend_from_slice(&law.real_fiber_dimension_after.to_le_bytes());
        }
        Ok(hash_framed_parts_512(
            CONSTRUCTION_MASKING_THEOREM_BINDING_DOMAIN,
            &[
                &self.contract_source_hash,
                &self.coefficient_map_binding,
                &self.public_input_binding,
                &self.masking_contract_binding,
                &self.disclosure_digest,
                &verifier_move_count.to_le_bytes(),
                &construction_commitment_count.to_le_bytes(),
                &self.exposed_output_coordinate_count.to_le_bytes(),
                &self.private_coordinate_count.to_le_bytes(),
                &self.joint_disclosure_rank.to_le_bytes(),
                &self.residual_fiber_dimension.to_le_bytes(),
                &self.shared_cross_epoch_query_overlap.to_le_bytes(),
                &law_bytes,
                &[self.exact_statistical_distance_numerator],
                &[self.exact_statistical_distance_denominator],
            ],
        ))
    }
}

/// The ideal random oracle is sealed inside this module. No production caller
/// can supply a tape, couple it to a witness, or mint a transcript from values.
trait CompactSealedIdealUniformOracle {
    /// Samples only the independently uniform extension-field coordinates
    /// named by an authority-minted image request. It never fabricates a
    /// constrained output vector.
    fn sample_independent_coordinates(
        &mut self,
        identity: CompactMaskingAttemptIdentity,
        step_ordinal: u32,
        coordinate_count: u64,
        coin_coordinate_start: u64,
    ) -> Result<Vec<CompactChallengeField>, CompactMaskingSimulatorError>;

    fn program_construction_commitment(
        &mut self,
        identity: CompactMaskingAttemptIdentity,
        embedding: CompactConstructionCommitmentEmbedding,
    ) -> Result<CompactConstructionCommitmentHandle, CompactMaskingSimulatorError>;
}

/// In-module addressed ideal oracle. The private key is never encoded into an
/// ideal transcript, and callers cannot supply a coordinate tape. Coordinate
/// addresses include the attempt/reset identity and the entropy step, so a
/// rewound suffix is domain-separated while an exact checkpoint replay is
/// reproducible.
#[derive(Clone)]
struct CompactAddressedIdealUniformOracle {
    private_key: [u8; 64],
}

fn sample_exact_goldilocks(
    mut candidate_at: impl FnMut(u32) -> u64,
) -> Result<Goldilocks, CompactMaskingSimulatorError> {
    for draw_ordinal in 0..PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT {
        let candidate = candidate_at(draw_ordinal);
        if candidate < Goldilocks::ORDER_U64 {
            return Ok(Goldilocks::from_u64(candidate));
        }
    }
    Err(CompactMaskingSimulatorError::IdealOracleRefused)
}

impl CompactAddressedIdealUniformOracle {
    const fn new(private_key: [u8; 64]) -> Self {
        Self { private_key }
    }

    fn binding(&self) -> [u8; 64] {
        hash_framed_parts_512(
            "sealed-lattice/proof/compact-adaptive-masking-private-key-binding/v1",
            &[&self.private_key],
        )
    }

    fn sample_coordinate(
        &self,
        domain: &[u8],
        identity: CompactMaskingAttemptIdentity,
        step_ordinal: u32,
        coin_coordinate: u64,
    ) -> Result<CompactChallengeField, CompactMaskingSimulatorError> {
        let extension_degree = <CompactChallengeField as BasedVectorSpace<Goldilocks>>::DIMENSION;
        let mut coefficients = Vec::with_capacity(extension_degree);
        for basis_coordinate in 0..extension_degree {
            coefficients.push(sample_exact_goldilocks(|draw_ordinal| {
                let mut shake = Shake::v256();
                shake.update(domain);
                shake.update(&self.private_key);
                shake.update(&identity.binding_bytes());
                shake.update(&step_ordinal.to_le_bytes());
                shake.update(&coin_coordinate.to_le_bytes());
                shake.update(&(basis_coordinate as u64).to_le_bytes());
                shake.update(&draw_ordinal.to_le_bytes());
                let mut bytes = [0_u8; 8];
                shake.finalize(&mut bytes);
                u64::from_le_bytes(bytes)
            })?);
        }
        Ok(CompactChallengeField::from_basis_coefficients_fn(
            |basis_coordinate| coefficients[basis_coordinate],
        ))
    }

    fn addressed_bytes(
        &self,
        domain: &[u8],
        identity: CompactMaskingAttemptIdentity,
        address_parts: &[&[u8]],
    ) -> [u8; 64] {
        let mut shake = Shake::v256();
        shake.update(domain);
        shake.update(&self.private_key);
        shake.update(&identity.binding_bytes());
        for part in address_parts {
            shake.update(&(part.len() as u64).to_le_bytes());
            shake.update(part);
        }
        let mut output = [0_u8; 64];
        shake.finalize(&mut output);
        output
    }
}

impl CompactSealedIdealUniformOracle for CompactAddressedIdealUniformOracle {
    fn sample_independent_coordinates(
        &mut self,
        identity: CompactMaskingAttemptIdentity,
        step_ordinal: u32,
        coordinate_count: u64,
        coin_coordinate_start: u64,
    ) -> Result<Vec<CompactChallengeField>, CompactMaskingSimulatorError> {
        let capacity = usize::try_from(coordinate_count)
            .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?;
        (0..coordinate_count)
            .map(|coordinate| {
                let absolute_coordinate = coin_coordinate_start
                    .checked_add(coordinate)
                    .ok_or(CompactMaskingSimulatorError::ArithmeticOverflow)?;
                self.sample_coordinate(
                    IDEAL_PRIVATE_COORDINATE_DOMAIN,
                    identity,
                    step_ordinal,
                    absolute_coordinate,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|mut coordinates| {
                coordinates.shrink_to(capacity);
                coordinates
            })
    }

    fn program_construction_commitment(
        &mut self,
        identity: CompactMaskingAttemptIdentity,
        embedding: CompactConstructionCommitmentEmbedding,
    ) -> Result<CompactConstructionCommitmentHandle, CompactMaskingSimulatorError> {
        let ordinal = embedding.commitment_ordinal.to_le_bytes();
        Ok(CompactConstructionCommitmentHandle(self.addressed_bytes(
            IDEAL_COMMITMENT_DOMAIN,
            identity,
            &[&ordinal],
        )))
    }
}

/// Abstract interaction engine. The streaming entropy authority is joined in
/// `advance` once it has authorized the actual malicious-verifier prefix.
pub(crate) struct CompactAdaptiveMaskingSimulator<'contract> {
    verifier_inputs: CompactPublicKeyVerifierInputs<'contract>,
    coefficient_maps: &'contract CompactMaskingCoefficientMapCertificate,
    contract_source_hash: Hash512,
    attempt: CompactAttemptState,
    retired_coin_ranges: Vec<CompactRetiredCoinRange>,
    retired_commitment_handles: Vec<CompactConstructionCommitmentHandle>,
    ideal_oracle: CompactAddressedIdealUniformOracle,
    public_covector_authority: Option<CompactFactorOnePublicCovectorAuthority<'contract>>,
}

impl<'contract> CompactAdaptiveMaskingSimulator<'contract> {
    pub(crate) fn new(
        verifier_inputs: CompactPublicKeyVerifierInputs<'contract>,
        coefficient_maps: &'contract CompactMaskingCoefficientMapCertificate,
        attempt_identifier: CompactMaskingAttemptIdentifier,
        initial_exposed_prefix_binding: [u8; 64],
        private_ideal_oracle_key: [u8; 64],
    ) -> Result<Self, CompactMaskingSimulatorError> {
        let contract_source_hash = verifier_inputs.canonical_source_hash()?;
        coefficient_maps
            .check()
            .map_err(|_| CompactMaskingSimulatorError::InvalidCoefficientMap)?;
        if coefficient_maps.certificate_digest() != contract_source_hash.into_bytes() {
            return Err(CompactMaskingSimulatorError::InvalidCoefficientMap);
        }
        Ok(Self {
            contract_source_hash,
            verifier_inputs,
            coefficient_maps,
            attempt: CompactAttemptState::new(attempt_identifier, initial_exposed_prefix_binding),
            retired_coin_ranges: Vec::new(),
            retired_commitment_handles: Vec::new(),
            ideal_oracle: CompactAddressedIdealUniformOracle::new(private_ideal_oracle_key),
            public_covector_authority: None,
        })
    }

    pub(crate) fn new_with_public_covector_authority(
        verifier_inputs: CompactPublicKeyVerifierInputs<'contract>,
        coefficient_maps: &'contract CompactMaskingCoefficientMapCertificate,
        attempt_identifier: CompactMaskingAttemptIdentifier,
        initial_exposed_prefix_binding: [u8; 64],
        private_ideal_oracle_key: [u8; 64],
        public_covector_authority: CompactFactorOnePublicCovectorAuthority<'contract>,
    ) -> Result<Self, CompactMaskingSimulatorError> {
        let mut simulator = Self::new(
            verifier_inputs,
            coefficient_maps,
            attempt_identifier,
            initial_exposed_prefix_binding,
            private_ideal_oracle_key,
        )?;
        if public_covector_authority.contract_source_hash()
            != simulator.contract_source_hash.into_bytes()
        {
            return Err(CompactMaskingSimulatorError::WrongTranscript);
        }
        simulator.public_covector_authority = Some(public_covector_authority);
        Ok(simulator)
    }

    pub(crate) fn checkpoint(
        &self,
    ) -> Result<CompactMaskingSimulationCheckpoint, CompactMaskingSimulatorError> {
        Ok(CompactMaskingSimulationCheckpoint {
            contract_source_hash: self.contract_source_hash,
            coefficient_map_binding: self.coefficient_maps.certificate_digest(),
            public_input_binding: self
                .public_covector_authority
                .as_ref()
                .map(CompactFactorOnePublicCovectorAuthority::public_input_binding),
            exposed_prefix_binding: prefix_binding(
                self.contract_source_hash,
                self.coefficient_maps.certificate_digest(),
                self.public_covector_authority
                    .as_ref()
                    .map(CompactFactorOnePublicCovectorAuthority::public_input_binding),
                self.attempt.attempt_identifier,
                self.attempt.reset_ordinal,
                self.attempt.initial_exposed_prefix_binding,
                &self.attempt.moves,
            )?,
            attempt: self.attempt.clone(),
            retired_coin_ranges: self.retired_coin_ranges.clone(),
            retired_commitment_handles: self.retired_commitment_handles.clone(),
            ideal_oracle_binding: self.ideal_oracle.binding(),
        })
    }

    pub(crate) fn restore(
        verifier_inputs: CompactPublicKeyVerifierInputs<'contract>,
        coefficient_maps: &'contract CompactMaskingCoefficientMapCertificate,
        checkpoint: CompactMaskingSimulationCheckpoint,
        private_ideal_oracle_key: [u8; 64],
    ) -> Result<Self, CompactMaskingSimulatorError> {
        let mut simulator = Self::new(
            verifier_inputs,
            coefficient_maps,
            checkpoint.attempt.attempt_identifier,
            checkpoint.attempt.initial_exposed_prefix_binding,
            private_ideal_oracle_key,
        )?;
        simulator.validate_checkpoint_authentication(&checkpoint)?;
        simulator.attempt = checkpoint.attempt;
        simulator.retired_coin_ranges = checkpoint.retired_coin_ranges;
        simulator.retired_commitment_handles = checkpoint.retired_commitment_handles;
        simulator.validate_attempt_prefix()?;
        Ok(simulator)
    }

    pub(crate) fn restore_with_public_covector_authority(
        verifier_inputs: CompactPublicKeyVerifierInputs<'contract>,
        coefficient_maps: &'contract CompactMaskingCoefficientMapCertificate,
        checkpoint: CompactMaskingSimulationCheckpoint,
        private_ideal_oracle_key: [u8; 64],
        public_covector_authority: CompactFactorOnePublicCovectorAuthority<'contract>,
    ) -> Result<Self, CompactMaskingSimulatorError> {
        let mut simulator = Self::new_with_public_covector_authority(
            verifier_inputs,
            coefficient_maps,
            checkpoint.attempt.attempt_identifier,
            checkpoint.attempt.initial_exposed_prefix_binding,
            private_ideal_oracle_key,
            public_covector_authority,
        )?;
        simulator.validate_checkpoint_authentication(&checkpoint)?;
        simulator.attempt = checkpoint.attempt;
        simulator.retired_coin_ranges = checkpoint.retired_coin_ranges;
        simulator.retired_commitment_handles = checkpoint.retired_commitment_handles;
        simulator.validate_attempt_prefix()?;
        Ok(simulator)
    }

    /// Security-game rewind only. This is not a resettable-ZK claim.
    ///
    /// The exact exposed prefix is reused. Every abandoned suffix coin range
    /// and construction-commitment handle is permanently retired, and a fresh reset
    /// ordinal addresses all subsequent ideal-oracle requests.
    pub(crate) fn rewind_security_game_suffix(
        &mut self,
        checkpoint: CompactMaskingSimulationCheckpoint,
    ) -> Result<(), CompactMaskingSimulatorError> {
        self.validate_checkpoint_authentication(&checkpoint)?;
        self.replay_validated_attempt_state(
            &checkpoint.attempt,
            &checkpoint.retired_coin_ranges,
            &checkpoint.retired_commitment_handles,
        )?;
        if checkpoint.attempt.attempt_identifier != self.attempt.attempt_identifier
            || !self.attempt.moves.starts_with(&checkpoint.attempt.moves)
            || checkpoint.attempt.moves.len() > self.attempt.moves.len()
        {
            return Err(CompactMaskingSimulatorError::WrongCheckpoint);
        }
        let next_reset_ordinal = self
            .attempt
            .reset_ordinal
            .checked_add(1)
            .ok_or(CompactMaskingSimulatorError::ArithmeticOverflow)?;
        if checkpoint.attempt.next_coin_coordinate < self.attempt.next_coin_coordinate {
            self.retired_coin_ranges.push(CompactRetiredCoinRange {
                identity: self.attempt_identity(),
                start: checkpoint.attempt.next_coin_coordinate,
                end: self.attempt.next_coin_coordinate,
            });
        }
        self.retired_commitment_handles.extend(
            self.attempt.moves[checkpoint.attempt.moves.len()..]
                .iter()
                .flat_map(|record| &record.conditioned_view.new_construction_commitments)
                .map(CompactConstructionCommitmentProgram::handle),
        );
        self.retired_commitment_handles.sort_unstable();
        self.retired_commitment_handles.dedup();
        self.attempt = checkpoint.attempt;
        self.attempt.reset_ordinal = next_reset_ordinal;
        self.validate_attempt_prefix()
    }

    pub(crate) fn begin_role18_covector_derivation(
        &self,
    ) -> Result<CompactFactorOnePublicCovectorDerivation, CompactMaskingSimulatorError> {
        let prefix = self.mint_semantic_prefix()?;
        self.public_covector_authority
            .as_ref()
            .ok_or(CompactMaskingSimulatorError::WrongTranscript)?
            .begin_prefix_derivation(prefix)
            .map_err(Into::into)
    }

    pub(crate) fn advance(
        &mut self,
        verifier: &mut impl CompactAdaptiveVerifier,
    ) -> Result<u32, CompactMaskingSimulatorError> {
        self.advance_inner(verifier, None)
    }

    pub(crate) fn advance_role18(
        &mut self,
        verifier: &mut impl CompactAdaptiveVerifier,
        authorization: &mut CompactFactorOneCarriedCovector,
    ) -> Result<u32, CompactMaskingSimulatorError> {
        self.advance_inner(verifier, Some(authorization))
    }

    pub(crate) fn finish(
        self,
    ) -> Result<CompactMaskingSimulationCheckpoint, CompactMaskingSimulatorError> {
        self.validate_terminal_prefix()?;
        self.checkpoint()
    }

    /// Finishes the fresh single-attempt Ideal experiment and derives the exact
    /// pathwise Real/Ideal distribution law. A reset or retired randomness range
    /// is intentionally outside this claim even though the lifecycle simulator
    /// can exercise and authenticate those operations separately.
    pub(crate) fn finish_construction_masking_theorem(
        self,
    ) -> Result<
        (
            CompactMaskingSimulationCheckpoint,
            CompactConstructionMaskingTheorem,
        ),
        CompactMaskingSimulatorError,
    > {
        let entropy_certificate = self.validate_terminal_prefix()?;
        let theorem = derive_construction_masking_theorem(&self, &entropy_certificate)?;
        let checkpoint = self.checkpoint()?;
        Ok((checkpoint, theorem))
    }

    fn validate_terminal_prefix(
        &self,
    ) -> Result<CompactMaskingEntropyCertificate, CompactMaskingSimulatorError> {
        let entropy_authority = self.replay_validated_attempt_prefix()?;
        if self.attempt.moves.len() != self.verifier_inputs.verifier_moves.len() {
            return Err(CompactMaskingSimulatorError::SimulationNotActive);
        }
        let identity = self.attempt_identity();
        let certificate = entropy_authority.finish()?;
        let mut disclosure_cursor = certificate.begin_disclosures(identity);
        for disclosure in self.attempt.moves.iter().flat_map(|record| {
            record
                .conditioned_view
                .disclosures
                .iter()
                .chain(&record.post_message_disclosures)
        }) {
            certificate.verify_simulator_disclosure(
                &mut disclosure_cursor,
                identity,
                &disclosure.entropy_step,
            )?;
        }
        disclosure_cursor.finish(&certificate, identity)?;
        if self.attempt.next_coin_coordinate != certificate.joint_disclosure_rank() {
            return Err(CompactMaskingSimulatorError::WrongTranscript);
        }
        let programmed_embeddings = self
            .attempt
            .moves
            .iter()
            .flat_map(|record| &record.conditioned_view.new_construction_commitments)
            .map(|program| program.embedding);
        if !programmed_embeddings.eq(self
            .coefficient_maps
            .construction_commitment_embeddings()
            .iter()
            .copied())
        {
            return Err(CompactMaskingSimulatorError::WrongCommitmentProgression);
        }
        Ok(certificate)
    }

    fn advance_inner(
        &mut self,
        verifier: &mut impl CompactAdaptiveVerifier,
        authorization: Option<&mut CompactFactorOneCarriedCovector>,
    ) -> Result<u32, CompactMaskingSimulatorError> {
        let move_index = self.attempt.moves.len();
        let verifier_move = self
            .verifier_inputs
            .verifier_moves
            .get(move_index)
            .cloned()
            .ok_or(CompactMaskingSimulatorError::SimulationNotActive)?;
        let identity = self.attempt_identity();
        let mut entropy_authority = self.replay_entropy_authority()?;
        let requirement = entropy_authority.next_base_claim_requirement()?;
        let (semantic_prefix, public_input_binding, base_fresh_claim) =
            match (requirement, authorization.as_deref()) {
                (None, None) => (None, None, None),
                (None, Some(_)) => {
                    return Err(CompactMaskingSimulatorError::InvalidRole18Authorization);
                }
                (Some(_), None) => {
                    return Err(CompactMaskingSimulatorError::Role18AuthorizationRequired);
                }
                (Some(requirement), Some(authorization)) => {
                    let authority = self
                        .public_covector_authority
                        .as_ref()
                        .ok_or(CompactMaskingSimulatorError::InvalidRole18Authorization)?;
                    let prefix = self.mint_semantic_prefix_for_requirement(requirement)?;
                    let public_input_binding = authority.public_input_binding();
                    if !authorization.authorizes(&prefix, public_input_binding) {
                        return Err(CompactMaskingSimulatorError::InvalidRole18Authorization);
                    }
                    let claim =
                        CompactBaseFreshClaimCoefficients::from_carried_covector(authorization)?;
                    if claim.epoch() != requirement.epoch()
                        || u64::try_from(claim.coefficients().len()).ok()
                            != Some(requirement.coefficient_count())
                    {
                        return Err(CompactMaskingSimulatorError::InvalidRole18Authorization);
                    }
                    (Some(prefix), Some(public_input_binding), Some(claim))
                }
            };
        let mut staged_attempt = self.attempt.clone();
        let mut staged_ideal_oracle = self.ideal_oracle.clone();
        let response_steps = entropy_authority
            .authorize_next_response(base_fresh_claim.as_ref())?
            .to_vec();
        let disclosures = sample_disclosures(
            &mut staged_ideal_oracle,
            CompactDisclosureSamplingContext {
                identity,
                authority: &entropy_authority,
                prior_moves: &staged_attempt.moves,
                current_response_disclosures: &[],
                retired_coin_ranges: &self.retired_coin_ranges,
            },
            &response_steps,
            &mut staged_attempt.next_coin_coordinate,
        )?;
        let new_construction_commitments = self.program_new_commitments(
            &mut staged_ideal_oracle,
            &staged_attempt,
            identity,
            &verifier_move,
        )?;
        let conditioned_view = CompactIdealConditionedView {
            preceding_prover_response_ordinal: verifier_move.preceding_prover_response_ordinal,
            disclosures,
            new_construction_commitments,
        };
        let message = verifier.choose_message(CompactAdaptiveVerifierView {
            verifier_move: &verifier_move,
            current_conditioned_view: &conditioned_view,
        });
        let query_steps = entropy_authority
            .ingest_verifier_message(verifier_move.ordinal, &message)
            .map_err(|_| CompactMaskingSimulatorError::InvalidVerifierMessage)?
            .to_vec();
        let post_message_disclosures = sample_disclosures(
            &mut staged_ideal_oracle,
            CompactDisclosureSamplingContext {
                identity,
                authority: &entropy_authority,
                prior_moves: &staged_attempt.moves,
                current_response_disclosures: &conditioned_view.disclosures,
                retired_coin_ranges: &self.retired_coin_ranges,
            },
            &query_steps,
            &mut staged_attempt.next_coin_coordinate,
        )?;
        staged_attempt.moves.push(CompactIdealMaskingMoveRecord {
            base_fresh_claim,
            conditioned_view,
            verifier_message: message,
            post_message_disclosures,
        });
        if let (Some(authorization), Some(prefix), Some(public_input_binding)) = (
            authorization,
            semantic_prefix.as_ref(),
            public_input_binding,
        ) {
            authorization.consume(prefix, public_input_binding)?;
        }
        self.attempt = staged_attempt;
        self.ideal_oracle = staged_ideal_oracle;
        Ok(verifier_move.ordinal)
    }

    fn replay_entropy_authority(
        &self,
    ) -> Result<CompactMaskingEntropyAuthority<'contract>, CompactMaskingSimulatorError> {
        self.replay_entropy_authority_for_attempt(&self.attempt)
    }

    fn replay_entropy_authority_for_attempt(
        &self,
        attempt: &CompactAttemptState,
    ) -> Result<CompactMaskingEntropyAuthority<'contract>, CompactMaskingSimulatorError> {
        let identity = attempt_identity(attempt);
        let mut authority = CompactMaskingEntropyAuthority::begin(
            copy_verifier_inputs(&self.verifier_inputs),
            self.coefficient_maps,
            identity,
        )?;
        for (move_index, record) in attempt.moves.iter().enumerate() {
            let expected_pre =
                authority.authorize_next_response(record.base_fresh_claim.as_ref())?;
            verify_authorized_steps(&record.conditioned_view.disclosures, expected_pre)?;
            let move_contract = self
                .verifier_inputs
                .verifier_moves
                .get(move_index)
                .ok_or(CompactMaskingSimulatorError::WrongCheckpoint)?;
            let expected_post = authority
                .ingest_verifier_message(move_contract.ordinal, &record.verifier_message)?;
            verify_authorized_steps(&record.post_message_disclosures, expected_post)?;
        }
        Ok(authority)
    }

    fn mint_semantic_prefix(
        &self,
    ) -> Result<CompactMaskingSemanticPrefix, CompactMaskingSimulatorError> {
        let entropy_authority = self.replay_entropy_authority()?;
        let requirement = entropy_authority
            .next_base_claim_requirement()?
            .ok_or(CompactMaskingSimulatorError::WrongTranscript)?;
        self.mint_semantic_prefix_for_requirement(requirement)
    }

    fn mint_semantic_prefix_for_requirement(
        &self,
        requirement: super::compact_masking_entropy::CompactBaseFreshClaimRequirement,
    ) -> Result<CompactMaskingSemanticPrefix, CompactMaskingSimulatorError> {
        let next_move = self
            .verifier_inputs
            .verifier_moves
            .get(self.attempt.moves.len())
            .ok_or(CompactMaskingSimulatorError::SimulationNotActive)?;
        let [role] = next_move.role_coordinates.as_slice() else {
            return Err(CompactMaskingSimulatorError::WrongTranscript);
        };
        if role.role_tag != 10
            || role.epoch != requirement.epoch()
            || role.batch_ordinal != 0
            || role.round_ordinal != 0
        {
            return Err(CompactMaskingSimulatorError::WrongTranscript);
        }
        CompactMaskingSemanticPrefix::from_validated_transcript(
            self.attempt_identity(),
            next_move.ordinal,
            role.epoch,
            self.contract_source_hash.into_bytes(),
            encode_moves(&self.attempt.moves)?.into_boxed_slice(),
            self.attempt
                .moves
                .iter()
                .map(|record| record.verifier_message.clone())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
        .map_err(|_| CompactMaskingSimulatorError::WrongTranscript)
    }

    fn program_new_commitments(
        &self,
        ideal_oracle: &mut impl CompactSealedIdealUniformOracle,
        attempt: &CompactAttemptState,
        identity: CompactMaskingAttemptIdentity,
        verifier_move: &CompactVerifierMoveContract,
    ) -> Result<Vec<CompactConstructionCommitmentProgram>, CompactMaskingSimulatorError> {
        let already_programmed = attempt.moves.iter().try_fold(0_usize, |count, record| {
            count
                .checked_add(record.conditioned_view.new_construction_commitments.len())
                .ok_or(CompactMaskingSimulatorError::ArithmeticOverflow)
        })?;
        let expected_count = usize::try_from(verifier_move.preceding_commitment_count)
            .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?;
        let embeddings = self
            .coefficient_maps
            .construction_commitment_embeddings()
            .get(already_programmed..expected_count)
            .ok_or(CompactMaskingSimulatorError::WrongCommitmentProgression)?;
        let mut programs = Vec::with_capacity(embeddings.len());
        for embedding in embeddings {
            if embedding.outer_response_ordinal != verifier_move.ordinal {
                return Err(CompactMaskingSimulatorError::WrongCommitmentEmbedding);
            }
            let handle = ideal_oracle.program_construction_commitment(identity, *embedding)?;
            if self.retired_commitment_handles.contains(&handle)
                || attempt
                    .moves
                    .iter()
                    .flat_map(|record| &record.conditioned_view.new_construction_commitments)
                    .any(|program| program.handle == handle)
                || programs
                    .iter()
                    .any(|program: &CompactConstructionCommitmentProgram| program.handle == handle)
            {
                return Err(if self.retired_commitment_handles.contains(&handle) {
                    CompactMaskingSimulatorError::ReusedCommitmentHandle
                } else {
                    CompactMaskingSimulatorError::WrongCommitmentProgression
                });
            }
            programs.push(CompactConstructionCommitmentProgram {
                embedding: *embedding,
                handle,
            });
        }
        Ok(programs)
    }

    fn attempt_identity(&self) -> CompactMaskingAttemptIdentity {
        attempt_identity(&self.attempt)
    }

    fn validate_checkpoint_authentication(
        &self,
        checkpoint: &CompactMaskingSimulationCheckpoint,
    ) -> Result<(), CompactMaskingSimulatorError> {
        if checkpoint.contract_source_hash != self.contract_source_hash
            || checkpoint.coefficient_map_binding != self.coefficient_maps.certificate_digest()
            || checkpoint.public_input_binding
                != self
                    .public_covector_authority
                    .as_ref()
                    .map(CompactFactorOnePublicCovectorAuthority::public_input_binding)
            || checkpoint.ideal_oracle_binding != self.ideal_oracle.binding()
            || checkpoint.exposed_prefix_binding
                != prefix_binding(
                    self.contract_source_hash,
                    self.coefficient_maps.certificate_digest(),
                    checkpoint.public_input_binding,
                    checkpoint.attempt.attempt_identifier,
                    checkpoint.attempt.reset_ordinal,
                    checkpoint.attempt.initial_exposed_prefix_binding,
                    &checkpoint.attempt.moves,
                )?
        {
            return Err(CompactMaskingSimulatorError::WrongCheckpoint);
        }
        Ok(())
    }

    fn validate_attempt_prefix(&self) -> Result<(), CompactMaskingSimulatorError> {
        self.replay_validated_attempt_prefix().map(|_| ())
    }

    fn replay_validated_attempt_prefix(
        &self,
    ) -> Result<CompactMaskingEntropyAuthority<'contract>, CompactMaskingSimulatorError> {
        self.replay_validated_attempt_state(
            &self.attempt,
            &self.retired_coin_ranges,
            &self.retired_commitment_handles,
        )
    }

    fn replay_validated_attempt_state(
        &self,
        attempt: &CompactAttemptState,
        retired_coin_ranges: &[CompactRetiredCoinRange],
        retired_commitment_handles: &[CompactConstructionCommitmentHandle],
    ) -> Result<CompactMaskingEntropyAuthority<'contract>, CompactMaskingSimulatorError> {
        if attempt.moves.len() > self.verifier_inputs.verifier_moves.len()
            || retired_coin_ranges
                .iter()
                .any(|range| range.start >= range.end)
            || retired_coin_ranges.windows(2).any(|ranges| {
                ranges[0].identity == ranges[1].identity && ranges[0].end > ranges[1].start
            })
            || retired_commitment_handles
                .windows(2)
                .any(|handles| handles[0] >= handles[1])
        {
            return Err(CompactMaskingSimulatorError::WrongCheckpoint);
        }
        let entropy_authority = self.replay_entropy_authority_for_attempt(attempt)?;
        let replayed_coin_coordinate = validate_move_prefix(
            &self.verifier_inputs,
            self.coefficient_maps,
            attempt_identity(attempt),
            &attempt.moves,
            retired_coin_ranges,
            retired_commitment_handles,
        )?;
        if replayed_coin_coordinate != attempt.next_coin_coordinate {
            return Err(CompactMaskingSimulatorError::WrongTranscript);
        }
        Ok(entropy_authority)
    }
}

fn derive_construction_masking_theorem(
    simulator: &CompactAdaptiveMaskingSimulator<'_>,
    entropy_certificate: &CompactMaskingEntropyCertificate,
) -> Result<CompactConstructionMaskingTheorem, CompactMaskingSimulatorError> {
    if simulator.attempt.reset_ordinal != 0
        || !simulator.retired_coin_ranges.is_empty()
        || !simulator.retired_commitment_handles.is_empty()
    {
        return Err(CompactMaskingSimulatorError::InvalidConstructionGameLaw);
    }
    let public_input_binding = simulator
        .public_covector_authority
        .as_ref()
        .map(CompactFactorOnePublicCovectorAuthority::public_input_binding)
        .ok_or(CompactMaskingSimulatorError::InvalidConstructionGameLaw)?;
    let disclosures = simulator
        .attempt
        .moves
        .iter()
        .flat_map(|record| {
            record
                .conditioned_view
                .disclosures
                .iter()
                .chain(&record.post_message_disclosures)
        })
        .collect::<Vec<_>>();
    if disclosures.len() != entropy_certificate.steps().len() {
        return Err(CompactMaskingSimulatorError::InvalidConstructionGameLaw);
    }

    let mut conditional_laws = Vec::with_capacity(disclosures.len());
    let mut exposed_output_coordinate_count = 0_u64;
    let mut real_fiber_dimension_before = entropy_certificate.private_coordinate_count();
    for (step_index, (disclosure, entropy_step)) in disclosures
        .iter()
        .zip(entropy_certificate.steps())
        .enumerate()
    {
        let ideal_coin_coordinate_end = disclosures
            .get(step_index + 1)
            .map_or(simulator.attempt.next_coin_coordinate, |next| {
                next.coin_coordinate_start
            });
        let ideal_uniform_coordinate_count = ideal_coin_coordinate_end
            .checked_sub(disclosure.coin_coordinate_start)
            .ok_or(CompactMaskingSimulatorError::InvalidConstructionGameLaw)?;
        let real_uniform_coordinate_count = entropy_step.conditional_rank();
        let real_fiber_dimension_after = real_fiber_dimension_before
            .checked_sub(real_uniform_coordinate_count)
            .ok_or(CompactMaskingSimulatorError::InvalidConstructionGameLaw)?;
        exposed_output_coordinate_count = exposed_output_coordinate_count
            .checked_add(entropy_step.output_coordinate_count())
            .ok_or(CompactMaskingSimulatorError::ArithmeticOverflow)?;
        if &disclosure.entropy_step != entropy_step
            || u64::try_from(disclosure.field_values.len()).ok()
                != Some(entropy_step.output_coordinate_count())
            || real_uniform_coordinate_count != ideal_uniform_coordinate_count
            || entropy_step.residual_entropy_dimension() != real_fiber_dimension_after
        {
            return Err(CompactMaskingSimulatorError::InvalidConstructionGameLaw);
        }
        conditional_laws.push(CompactMaskingConditionalGameLaw {
            step_ordinal: entropy_step.ordinal(),
            verifier_move_ordinal: entropy_step.verifier_move_ordinal(),
            output_coordinate_count: entropy_step.output_coordinate_count(),
            real_uniform_coordinate_count,
            ideal_uniform_coordinate_count,
            cumulative_real_rank: entropy_step.cumulative_rank(),
            real_fiber_dimension_before,
            real_fiber_dimension_after,
        });
        real_fiber_dimension_before = real_fiber_dimension_after;
    }

    let construction_commitment_count = simulator
        .attempt
        .moves
        .iter()
        .map(|record| record.conditioned_view.new_construction_commitments.len())
        .sum();
    let mut theorem = CompactConstructionMaskingTheorem {
        contract_source_hash: simulator.contract_source_hash.into_bytes(),
        coefficient_map_binding: simulator.coefficient_maps.certificate_digest(),
        public_input_binding,
        masking_contract_binding: entropy_certificate.contract_binding(),
        disclosure_digest: entropy_certificate.disclosure_digest(),
        verifier_move_count: simulator.verifier_inputs.verifier_moves.len(),
        construction_commitment_count,
        exposed_output_coordinate_count,
        private_coordinate_count: entropy_certificate.private_coordinate_count(),
        joint_disclosure_rank: entropy_certificate.joint_disclosure_rank(),
        residual_fiber_dimension: entropy_certificate.residual_conditional_entropy_dimension(),
        shared_cross_epoch_query_overlap: entropy_certificate.shared_cross_epoch_query_overlap(),
        conditional_laws,
        exact_statistical_distance_numerator: 0,
        exact_statistical_distance_denominator: 1,
        theorem_binding: [0_u8; 64],
    };
    theorem.theorem_binding = theorem.recomputed_binding()?;
    theorem.check()?;
    Ok(theorem)
}

fn attempt_identity(attempt: &CompactAttemptState) -> CompactMaskingAttemptIdentity {
    CompactMaskingAttemptIdentity::new(
        attempt.attempt_identifier,
        attempt.reset_ordinal,
        attempt.initial_exposed_prefix_binding,
    )
}

struct CompactDisclosureSamplingContext<'a, 'contract> {
    identity: CompactMaskingAttemptIdentity,
    authority: &'a CompactMaskingEntropyAuthority<'contract>,
    prior_moves: &'a [CompactIdealMaskingMoveRecord],
    current_response_disclosures: &'a [CompactIdealDisclosure],
    retired_coin_ranges: &'a [CompactRetiredCoinRange],
}

fn sample_disclosures(
    oracle: &mut impl CompactSealedIdealUniformOracle,
    context: CompactDisclosureSamplingContext<'_, '_>,
    steps: &[CompactMaskingEntropyStep],
    next_coin_coordinate: &mut u64,
) -> Result<Vec<CompactIdealDisclosure>, CompactMaskingSimulatorError> {
    let mut disclosures = Vec::with_capacity(steps.len());
    for (step_index, step) in steps.iter().enumerate() {
        let request = context.authority.ideal_image_request(step)?;
        if request.attempt_identity() != context.identity
            || request.step_ordinal() != step.ordinal()
            || request.verifier_move_ordinal() != step.verifier_move_ordinal()
            || request.output_coordinate_count() != step.output_coordinate_count()
            || request.independent_coordinate_count() != step.conditional_rank()
            || request.image() != step.image()
        {
            return Err(CompactMaskingSimulatorError::IdealOracleRefused);
        }
        let start = *next_coin_coordinate;
        let end = start
            .checked_add(request.independent_coordinate_count())
            .ok_or(CompactMaskingSimulatorError::ArithmeticOverflow)?;
        if context
            .retired_coin_ranges
            .iter()
            .any(|range| range.overlaps(context.identity, start, end))
        {
            return Err(CompactMaskingSimulatorError::ReusedCoinCoordinate);
        }
        let independent_coordinates = oracle.sample_independent_coordinates(
            context.identity,
            request.step_ordinal(),
            request.independent_coordinate_count(),
            start,
        )?;
        let field_values = match request.image() {
            CompactMaskingDisclosureImage::FullCoordinateSpace => independent_coordinates,
            CompactMaskingDisclosureImage::LinearClaimFiber {
                pivot_output_coordinate,
            } => sample_linear_claim_fiber(
                CompactLinearClaimFiberContext {
                    authority: context.authority,
                    step,
                    pivot_output_coordinate,
                    prior_moves: context.prior_moves,
                    current_response_disclosures: context.current_response_disclosures,
                    current_disclosures: &disclosures,
                    remaining_steps: &steps[step_index + 1..],
                },
                independent_coordinates,
            )?,
            CompactMaskingDisclosureImage::CoefficientMapImage {
                map_ordinal,
                first_output_coordinate,
            } => {
                let preceding_output_values = retained_map_prefix(
                    map_ordinal,
                    first_output_coordinate,
                    context.prior_moves,
                    context.current_response_disclosures,
                    &disclosures,
                )?;
                let coefficient_request =
                    if step.kind() == CompactMaskingDisclosureKind::CfwOuterEvaluations {
                        let mut terminal_disclosures = disclosures.iter().filter(|disclosure| {
                            disclosure.entropy_step.kind()
                                == CompactMaskingDisclosureKind::CfwInnerTerminal
                        });
                        let terminal_disclosure = terminal_disclosures
                            .next()
                            .ok_or(CompactMaskingSimulatorError::WrongTranscript)?;
                        if terminal_disclosures.next().is_some() {
                            return Err(CompactMaskingSimulatorError::WrongTranscript);
                        }
                        let terminal_values: &[CompactChallengeField; COMPACT_CFW_MATRIX_COUNT] =
                            terminal_disclosure
                                .field_values
                                .as_slice()
                                .try_into()
                                .map_err(|_| CompactMaskingSimulatorError::WrongTranscript)?;
                        context.authority.prepare_cfw_final_outer_image(
                            step,
                            &preceding_output_values,
                            terminal_values,
                        )?
                    } else {
                        let retained_mirror_coefficients = retained_mirror_coefficients(
                            step.kind(),
                            context.prior_moves,
                            context.current_response_disclosures,
                            &disclosures,
                        )?;
                        context.authority.prepare_coefficient_image(
                            step,
                            &preceding_output_values,
                            retained_mirror_coefficients.as_deref(),
                        )?
                    };
                if coefficient_request.output_coordinate_count()
                    != request.output_coordinate_count()
                    || coefficient_request.independent_coordinate_count()
                        != request.independent_coordinate_count()
                {
                    return Err(CompactMaskingSimulatorError::IdealOracleRefused);
                }
                context.authority.execute_coefficient_image(
                    step,
                    &coefficient_request,
                    &independent_coordinates,
                )?
            }
        };
        if u64::try_from(field_values.len()).ok() != Some(step.output_coordinate_count()) {
            return Err(CompactMaskingSimulatorError::IdealOracleRefused);
        }
        disclosures.push(CompactIdealDisclosure {
            entropy_step: step.clone(),
            field_values,
            coin_coordinate_start: start,
        });
        *next_coin_coordinate = end;
    }
    Ok(disclosures)
}

fn retained_map_prefix(
    map_ordinal: usize,
    first_output_coordinate: u64,
    prior_moves: &[CompactIdealMaskingMoveRecord],
    current_response_disclosures: &[CompactIdealDisclosure],
    current_disclosures: &[CompactIdealDisclosure],
) -> Result<Vec<CompactChallengeField>, CompactMaskingSimulatorError> {
    let expected = usize::try_from(first_output_coordinate)
        .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?;
    if expected == 0 {
        return Ok(Vec::new());
    }
    let values = prior_moves
        .iter()
        .flat_map(|record| {
            record
                .conditioned_view
                .disclosures
                .iter()
                .chain(&record.post_message_disclosures)
        })
        .chain(current_response_disclosures)
        .chain(current_disclosures)
        .filter(|disclosure| {
            matches!(
                disclosure.entropy_step.image(),
                CompactMaskingDisclosureImage::CoefficientMapImage {
                    map_ordinal: disclosure_map_ordinal,
                    ..
                } if disclosure_map_ordinal == map_ordinal
            )
        })
        .flat_map(|disclosure| disclosure.field_values.iter().copied())
        .collect::<Vec<_>>();
    if values.len() != expected {
        return Err(CompactMaskingSimulatorError::WrongTranscript);
    }
    Ok(values)
}

fn retained_mirror_coefficients(
    kind: CompactMaskingDisclosureKind,
    prior_moves: &[CompactIdealMaskingMoveRecord],
    current_response_disclosures: &[CompactIdealDisclosure],
    current_disclosures: &[CompactIdealDisclosure],
) -> Result<Option<Vec<CompactChallengeField>>, CompactMaskingSimulatorError> {
    let disclosures = prior_moves
        .iter()
        .flat_map(|record| {
            record
                .conditioned_view
                .disclosures
                .iter()
                .chain(&record.post_message_disclosures)
        })
        .chain(current_response_disclosures)
        .chain(current_disclosures)
        .collect::<Vec<_>>();
    match kind {
        CompactMaskingDisclosureKind::FreshSourceQueries { epoch } => {
            let message = unique_retained_disclosure(
                &disclosures,
                CompactMaskingDisclosureKind::BaseBlindedSourceMessage { epoch },
            )?;
            let randomness = unique_retained_disclosure(
                &disclosures,
                CompactMaskingDisclosureKind::BaseBlindedSourceRandomness { epoch },
            )?;
            if message.entropy_step.ordinal() >= randomness.entropy_step.ordinal() {
                return Err(CompactMaskingSimulatorError::WrongTranscript);
            }
            let coordinate_count = message
                .field_values
                .len()
                .checked_add(randomness.field_values.len())
                .ok_or(CompactMaskingSimulatorError::ArithmeticOverflow)?;
            let mut coefficients = Vec::with_capacity(coordinate_count);
            coefficients.extend_from_slice(&message.field_values);
            coefficients.extend_from_slice(&randomness.field_values);
            Ok(Some(coefficients))
        }
        CompactMaskingDisclosureKind::FreshMaskQueries {
            epoch,
            group_ordinal,
        } => Ok(Some(
            unique_retained_disclosure(
                &disclosures,
                CompactMaskingDisclosureKind::BaseBlindedMaskGroup {
                    epoch,
                    group_ordinal,
                },
            )?
            .field_values
            .clone(),
        )),
        _ => Ok(None),
    }
}

fn unique_retained_disclosure<'a>(
    disclosures: &[&'a CompactIdealDisclosure],
    kind: CompactMaskingDisclosureKind,
) -> Result<&'a CompactIdealDisclosure, CompactMaskingSimulatorError> {
    let mut matches = disclosures
        .iter()
        .copied()
        .filter(|disclosure| disclosure.entropy_step.kind() == kind);
    let disclosure = matches
        .next()
        .ok_or(CompactMaskingSimulatorError::WrongTranscript)?;
    if matches.next().is_some()
        || u64::try_from(disclosure.field_values.len()).ok()
            != Some(disclosure.entropy_step.output_coordinate_count())
    {
        return Err(CompactMaskingSimulatorError::WrongTranscript);
    }
    Ok(disclosure)
}

struct CompactLinearClaimFiberContext<'a, 'contract> {
    authority: &'a CompactMaskingEntropyAuthority<'contract>,
    step: &'a CompactMaskingEntropyStep,
    pivot_output_coordinate: u64,
    prior_moves: &'a [CompactIdealMaskingMoveRecord],
    current_response_disclosures: &'a [CompactIdealDisclosure],
    current_disclosures: &'a [CompactIdealDisclosure],
    remaining_steps: &'a [CompactMaskingEntropyStep],
}

fn sample_linear_claim_fiber(
    context: CompactLinearClaimFiberContext<'_, '_>,
    independent_coordinates: Vec<CompactChallengeField>,
) -> Result<Vec<CompactChallengeField>, CompactMaskingSimulatorError> {
    let covector = context.authority.reveal_output_covector(context.step)?;
    let output_count = usize::try_from(context.step.output_coordinate_count())
        .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?;
    let pivot = usize::try_from(context.pivot_output_coordinate)
        .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?;
    if covector.len() != output_count
        || pivot >= output_count
        || covector[pivot] == CompactChallengeField::ZERO
        || independent_coordinates.len() + 1 != output_count
    {
        return Err(CompactMaskingSimulatorError::IdealOracleRefused);
    }
    let epoch = match context.step.kind() {
        CompactMaskingDisclosureKind::BaseBlindedSourceMessage { epoch }
        | CompactMaskingDisclosureKind::BaseBlindedMaskGroup { epoch, .. } => epoch,
        _ => return Err(CompactMaskingSimulatorError::IdealOracleRefused),
    };
    let mut target = base_claim_target(
        epoch,
        context.prior_moves,
        context.current_response_disclosures,
        context.current_disclosures,
    )?;
    for disclosure in context
        .current_response_disclosures
        .iter()
        .chain(context.current_disclosures)
        .filter(|disclosure| disclosure.entropy_step.kind().reveal_epoch() == Some(epoch))
    {
        let preceding_covector = context
            .authority
            .reveal_output_covector(&disclosure.entropy_step)?;
        if preceding_covector.len() != disclosure.field_values.len() {
            return Err(CompactMaskingSimulatorError::IdealOracleRefused);
        }
        target -= preceding_covector
            .iter()
            .zip(&disclosure.field_values)
            .map(|(coefficient, value)| *coefficient * *value)
            .sum::<CompactChallengeField>();
    }
    for remaining in context
        .remaining_steps
        .iter()
        .filter(|remaining| remaining.kind().reveal_epoch() == Some(epoch))
    {
        if context
            .authority
            .reveal_output_covector(remaining)?
            .iter()
            .any(|coefficient| *coefficient != CompactChallengeField::ZERO)
        {
            return Err(CompactMaskingSimulatorError::IdealOracleRefused);
        }
    }
    let mut output = Vec::with_capacity(output_count);
    let mut independent = independent_coordinates.into_iter();
    for coordinate in 0..output_count {
        output.push(if coordinate == pivot {
            CompactChallengeField::ZERO
        } else {
            independent
                .next()
                .ok_or(CompactMaskingSimulatorError::IdealOracleRefused)?
        });
    }
    let partial = output
        .iter()
        .zip(&covector)
        .map(|(value, coefficient)| *value * *coefficient)
        .sum::<CompactChallengeField>();
    output[pivot] = (target - partial) * covector[pivot].inverse();
    Ok(output)
}

fn base_claim_target(
    epoch: u8,
    prior_moves: &[CompactIdealMaskingMoveRecord],
    current_response_disclosures: &[CompactIdealDisclosure],
    current_disclosures: &[CompactIdealDisclosure],
) -> Result<CompactChallengeField, CompactMaskingSimulatorError> {
    let mut matches = prior_moves
        .iter()
        .flat_map(|record| {
            record
                .conditioned_view
                .disclosures
                .iter()
                .chain(&record.post_message_disclosures)
        })
        .chain(current_response_disclosures)
        .chain(current_disclosures)
        .filter(|disclosure| {
            disclosure.entropy_step.kind() == CompactMaskingDisclosureKind::BaseFreshClaim { epoch }
        });
    let target = *matches
        .next()
        .and_then(|disclosure| disclosure.field_values.first())
        .ok_or(CompactMaskingSimulatorError::WrongTranscript)?;
    if matches.next().is_some() {
        return Err(CompactMaskingSimulatorError::WrongTranscript);
    }
    Ok(target)
}

fn validate_move_prefix(
    verifier_inputs: &CompactPublicKeyVerifierInputs<'_>,
    coefficient_maps: &CompactMaskingCoefficientMapCertificate,
    identity: CompactMaskingAttemptIdentity,
    moves: &[CompactIdealMaskingMoveRecord],
    retired_coin_ranges: &[CompactRetiredCoinRange],
    retired_commitment_handles: &[CompactConstructionCommitmentHandle],
) -> Result<u64, CompactMaskingSimulatorError> {
    let mut next_coin_coordinate = 0_u64;
    let mut commitment_count = 0_usize;
    let mut handles = Vec::new();
    for (move_index, record) in moves.iter().enumerate() {
        let move_contract = verifier_inputs
            .verifier_moves
            .get(move_index)
            .ok_or(CompactMaskingSimulatorError::WrongTranscript)?;
        if record.conditioned_view.preceding_prover_response_ordinal
            != move_contract.preceding_prover_response_ordinal
        {
            return Err(CompactMaskingSimulatorError::WrongTranscript);
        }
        let expected_embeddings = coefficient_maps
            .construction_commitment_embeddings()
            .get(
                commitment_count
                    ..usize::try_from(move_contract.preceding_commitment_count)
                        .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?,
            )
            .ok_or(CompactMaskingSimulatorError::WrongCommitmentProgression)?;
        if record.conditioned_view.new_construction_commitments.len() != expected_embeddings.len() {
            return Err(CompactMaskingSimulatorError::WrongCommitmentProgression);
        }
        for (program, embedding) in record
            .conditioned_view
            .new_construction_commitments
            .iter()
            .zip(expected_embeddings)
        {
            if program.embedding != *embedding
                || handles.contains(&program.handle)
                || retired_commitment_handles.contains(&program.handle)
            {
                return Err(CompactMaskingSimulatorError::WrongCommitmentEmbedding);
            }
            handles.push(program.handle);
        }
        commitment_count += expected_embeddings.len();
        validate_disclosure_coordinates(
            &record.conditioned_view.disclosures,
            identity,
            &mut next_coin_coordinate,
            retired_coin_ranges,
        )?;
        validate_disclosure_coordinates(
            &record.post_message_disclosures,
            identity,
            &mut next_coin_coordinate,
            retired_coin_ranges,
        )?;
    }
    let expected_commitment_count = moves
        .last()
        .and_then(|_| verifier_inputs.verifier_moves.get(moves.len() - 1))
        .map_or(0, |last_completed_move| {
            last_completed_move.preceding_commitment_count
        });
    if u32::try_from(commitment_count).ok() != Some(expected_commitment_count) {
        return Err(CompactMaskingSimulatorError::WrongCommitmentProgression);
    }
    Ok(next_coin_coordinate)
}

fn validate_disclosure_coordinates(
    disclosures: &[CompactIdealDisclosure],
    identity: CompactMaskingAttemptIdentity,
    next_coin_coordinate: &mut u64,
    retired_coin_ranges: &[CompactRetiredCoinRange],
) -> Result<(), CompactMaskingSimulatorError> {
    for disclosure in disclosures {
        let end = disclosure
            .coin_coordinate_start
            .checked_add(disclosure.entropy_step.conditional_rank())
            .ok_or(CompactMaskingSimulatorError::ArithmeticOverflow)?;
        if disclosure.coin_coordinate_start != *next_coin_coordinate
            || u64::try_from(disclosure.field_values.len()).ok()
                != Some(disclosure.entropy_step.output_coordinate_count())
            || retired_coin_ranges
                .iter()
                .any(|range| range.overlaps(identity, disclosure.coin_coordinate_start, end))
        {
            return Err(CompactMaskingSimulatorError::WrongTranscript);
        }
        *next_coin_coordinate = end;
    }
    Ok(())
}

fn prefix_binding(
    contract_source_hash: Hash512,
    coefficient_map_binding: [u8; 64],
    public_input_binding: Option<[u8; 64]>,
    attempt_identifier: CompactMaskingAttemptIdentifier,
    reset_ordinal: u32,
    initial_exposed_prefix_binding: [u8; 64],
    moves: &[CompactIdealMaskingMoveRecord],
) -> Result<[u8; 64], CompactMaskingSimulatorError> {
    let reset_bytes = reset_ordinal.to_le_bytes();
    let moves_bytes = encode_moves(moves)?;
    let mut public_input_bytes = [0_u8; 65];
    if let Some(binding) = public_input_binding {
        public_input_bytes[0] = 1;
        public_input_bytes[1..].copy_from_slice(&binding);
    }
    Ok(hash_framed_parts_512(
        IDEAL_PREFIX_BINDING_DOMAIN,
        &[
            contract_source_hash.as_bytes(),
            &coefficient_map_binding,
            &public_input_bytes,
            &attempt_identifier,
            &reset_bytes,
            &initial_exposed_prefix_binding,
            &moves_bytes,
        ],
    ))
}

fn encode_moves(
    moves: &[CompactIdealMaskingMoveRecord],
) -> Result<Vec<u8>, CompactMaskingSimulatorError> {
    let mut bytes = encoded_move_count_prefix(moves.len())?;
    for record in moves {
        encode_exposed_move_prefix(&mut bytes, record)?;
        match &record.base_fresh_claim {
            None => bytes.push(0),
            Some(claim) => {
                bytes.push(1);
                bytes.push(claim.epoch());
                bytes.extend_from_slice(
                    &u64::try_from(claim.coefficients().len())
                        .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?
                        .to_le_bytes(),
                );
                for coefficient in claim.coefficients() {
                    let production =
                        super::compact_cfw::compact_challenge_to_production(*coefficient)
                            .map_err(|_| CompactMaskingSimulatorError::WrongTranscript)?;
                    for coordinate in production.canonical_coordinates() {
                        bytes.extend_from_slice(&coordinate.to_le_bytes());
                    }
                }
            }
        }
        encode_exposed_move_suffix(&mut bytes, record)?;
    }
    Ok(bytes)
}

fn encoded_move_count_prefix(move_count: usize) -> Result<Vec<u8>, CompactMaskingSimulatorError> {
    Ok(u64::try_from(move_count)
        .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?
        .to_le_bytes()
        .to_vec())
}

fn encode_exposed_move_prefix(
    bytes: &mut Vec<u8>,
    record: &CompactIdealMaskingMoveRecord,
) -> Result<(), CompactMaskingSimulatorError> {
    bytes.extend_from_slice(
        &record
            .conditioned_view
            .preceding_prover_response_ordinal
            .to_le_bytes(),
    );
    encode_disclosures(bytes, &record.conditioned_view.disclosures)
}

fn encode_exposed_move_suffix(
    bytes: &mut Vec<u8>,
    record: &CompactIdealMaskingMoveRecord,
) -> Result<(), CompactMaskingSimulatorError> {
    bytes.extend_from_slice(
        &u64::try_from(record.conditioned_view.new_construction_commitments.len())
            .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for program in &record.conditioned_view.new_construction_commitments {
        encode_embedding(bytes, program.embedding);
        bytes.extend_from_slice(program.handle.as_bytes());
    }
    encode_verifier_message(bytes, &record.verifier_message)?;
    encode_disclosures(bytes, &record.post_message_disclosures)
}

fn encode_disclosures(
    bytes: &mut Vec<u8>,
    disclosures: &[CompactIdealDisclosure],
) -> Result<(), CompactMaskingSimulatorError> {
    bytes.extend_from_slice(
        &u64::try_from(disclosures.len())
            .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for disclosure in disclosures {
        bytes.extend_from_slice(&disclosure.entropy_step.ordinal().to_le_bytes());
        bytes.extend_from_slice(&disclosure.coin_coordinate_start.to_le_bytes());
        bytes.extend_from_slice(
            &u64::try_from(disclosure.field_values.len())
                .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for value in &disclosure.field_values {
            for coordinate in
                <CompactChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                    value,
                )
            {
                bytes.extend_from_slice(&coordinate.as_canonical_u64().to_le_bytes());
            }
        }
    }
    Ok(())
}

fn encode_embedding(bytes: &mut Vec<u8>, embedding: CompactConstructionCommitmentEmbedding) {
    bytes.extend_from_slice(&embedding.commitment_ordinal.to_le_bytes());
    bytes.extend_from_slice(&embedding.outer_response_ordinal.to_le_bytes());
    bytes.extend_from_slice(&embedding.component_ordinal.to_le_bytes());
    bytes.push(embedding.semantic_role as u8);
    bytes.extend_from_slice(&[
        embedding.component_role.role_tag,
        embedding.component_role.epoch,
        embedding.component_role.batch_ordinal,
    ]);
    bytes.extend_from_slice(&embedding.component_role.round_ordinal.to_le_bytes());
    match embedding.ownership {
        CompactConstructionCommitmentOwnership::OwnedByEpoch { epoch } => {
            bytes.push(0);
            bytes.push(epoch);
        }
        CompactConstructionCommitmentOwnership::OwnedByPreChallengeEpochReusedByMainEpoch => {
            bytes.push(1);
        }
    }
    match embedding.query_source {
        CompactCommitmentQuerySource::Component => bytes.push(0),
        CompactCommitmentQuerySource::SharedCrossEpochUnion {
            owned_pre_challenge,
            reused_main,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(
                &owned_pre_challenge
                    .logical_verifier_move_ordinal
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(
                &owned_pre_challenge
                    .distinct_query_group_ordinal
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(&reused_main.logical_verifier_move_ordinal.to_le_bytes());
            bytes.extend_from_slice(&reused_main.distinct_query_group_ordinal.to_le_bytes());
        }
    }
}

fn encode_verifier_message(
    bytes: &mut Vec<u8>,
    message: &DecodedFixedUniformVerifierMessage,
) -> Result<(), CompactMaskingSimulatorError> {
    bytes.extend_from_slice(
        &u64::try_from(message.extension_elements().len())
            .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for element in message.extension_elements() {
        for coordinate in element.canonical_coordinates() {
            bytes.extend_from_slice(&coordinate.to_le_bytes());
        }
    }
    bytes.extend_from_slice(
        &u64::try_from(message.base_field_elements().len())
            .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for element in message.base_field_elements() {
        bytes.extend_from_slice(&element.canonical().to_le_bytes());
    }
    bytes.extend_from_slice(
        &u64::try_from(message.distinct_query_groups().len())
            .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for group in message.distinct_query_groups() {
        bytes.extend_from_slice(
            &u64::try_from(group.len())
                .map_err(|_| CompactMaskingSimulatorError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for query in group {
            bytes.extend_from_slice(&query.to_le_bytes());
        }
    }
    Ok(())
}

fn verify_authorized_steps(
    disclosures: &[CompactIdealDisclosure],
    expected_steps: &[CompactMaskingEntropyStep],
) -> Result<(), CompactMaskingSimulatorError> {
    if disclosures.len() != expected_steps.len()
        || disclosures
            .iter()
            .zip(expected_steps)
            .any(|(disclosure, step)| disclosure.entropy_step != *step)
    {
        return Err(CompactMaskingSimulatorError::WrongTranscript);
    }
    Ok(())
}

fn copy_verifier_inputs<'contract>(
    inputs: &CompactPublicKeyVerifierInputs<'contract>,
) -> CompactPublicKeyVerifierInputs<'contract> {
    CompactPublicKeyVerifierInputs {
        relation: inputs.relation,
        cfw_configuration: inputs.cfw_configuration,
        statement_layout: inputs.statement_layout,
        public_input_wire_geometry: inputs.public_input_wire_geometry,
        proof_wire_geometry: inputs.proof_wire_geometry,
        response_merkle_geometries: inputs.response_merkle_geometries,
        response_component_roles: inputs.response_component_roles,
        checkpoint_schedule: inputs.checkpoint_schedule,
        verifier_moves: inputs.verifier_moves,
        whir_epochs: inputs.whir_epochs,
        whir_folds: inputs.whir_folds,
    }
}

#[cfg(test)]
mod tests {
    use super::super::compact_cfw::compact_challenge_to_production;
    use super::super::compact_masking_coefficient_maps::derive_compact_masking_coefficient_map_certificate;
    use super::super::compact_masking_entropy::selected_test_compact_masking_entropy_certificate;
    use super::super::compact_masking_public_covector::CompactFactorOnePublicCovectorPoll;
    use super::super::compact_proof_contract::selected_compact_public_key_proof_contract;
    use super::super::compact_proof_wire::{
        CompactPublicInputBindings, encode_compact_public_input,
    };
    use super::super::compact_public_key_verifier::{
        CompactPublicKeyTransportError, VerifiedCompactPublicInputTransport,
        validate_selected_compact_public_input_transport,
    };
    use super::super::field::{ProofBaseFieldElement, ProofChallengeExtensionElement};
    use super::super::fixed_uniform_verifier_message::FixedUniformVerifierMessageGeometry;
    use super::*;

    struct SelectedAdversarialVerifier;

    impl CompactAdaptiveVerifier for SelectedAdversarialVerifier {
        fn choose_message(
            &mut self,
            view: CompactAdaptiveVerifierView<'_>,
        ) -> DecodedFixedUniformVerifierMessage {
            selected_adversarial_message(view.verifier_move())
        }
    }

    fn selected_adversarial_message(
        verifier_move: &CompactVerifierMoveContract,
    ) -> DecodedFixedUniformVerifierMessage {
        selected_adversarial_message_with_offset(verifier_move, 0)
    }

    fn selected_adversarial_message_with_offset(
        verifier_move: &CompactVerifierMoveContract,
        extension_offset: u64,
    ) -> DecodedFixedUniformVerifierMessage {
        let geometry = &verifier_move.message_geometry;
        let extension_elements = (0..geometry.extension_output_count())
            .map(|ordinal| {
                ProofChallengeExtensionElement::from_canonical_coordinates([
                    100 + u64::from(verifier_move.ordinal) * 1_000 + ordinal + extension_offset,
                    1,
                    2,
                    3,
                    5,
                ])
                .expect("canonical challenge")
            })
            .collect();
        let base_field_elements = (0..geometry.base_field_output_count())
            .map(|ordinal| {
                ProofBaseFieldElement::from_canonical(17 + ordinal).expect("canonical base element")
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
        .expect("typed adversarial verifier message")
    }

    struct PrefixVariantVerifier;

    impl CompactAdaptiveVerifier for PrefixVariantVerifier {
        fn choose_message(
            &mut self,
            view: CompactAdaptiveVerifierView<'_>,
        ) -> DecodedFixedUniformVerifierMessage {
            selected_adversarial_message_with_offset(
                view.verifier_move(),
                u64::from(view.verifier_move().ordinal == 0),
            )
        }
    }

    fn wrong_shape_adversarial_message(
        verifier_move: &CompactVerifierMoveContract,
    ) -> DecodedFixedUniformVerifierMessage {
        let extension_output_count = verifier_move
            .message_geometry
            .extension_output_count()
            .checked_add(1)
            .expect("selected extension count increments");
        let wrong_geometry =
            FixedUniformVerifierMessageGeometry::new(extension_output_count, 0, 0, Vec::new())
                .expect("nonempty wrong message geometry");
        let extension_elements = (0..extension_output_count)
            .map(|ordinal| {
                ProofChallengeExtensionElement::from_canonical_coordinates([
                    500 + ordinal,
                    1,
                    0,
                    0,
                    0,
                ])
                .expect("canonical wrong-shape challenge")
            })
            .collect();
        DecodedFixedUniformVerifierMessage::from_adversarial_values(
            &wrong_geometry,
            extension_elements,
            Vec::new(),
            Vec::new(),
        )
        .expect("typed message for the wrong geometry")
    }

    #[derive(Default)]
    struct InvalidThenValidVerifier {
        exposed_conditioned_views: Vec<CompactIdealConditionedView>,
        invalid_message_move_ordinal: Option<u32>,
    }

    impl CompactAdaptiveVerifier for InvalidThenValidVerifier {
        fn choose_message(
            &mut self,
            view: CompactAdaptiveVerifierView<'_>,
        ) -> DecodedFixedUniformVerifierMessage {
            let issue_invalid_message = self.invalid_message_move_ordinal.is_none()
                && !view.current_conditioned_view().disclosures.is_empty()
                && !view
                    .current_conditioned_view()
                    .new_construction_commitments
                    .is_empty();
            self.exposed_conditioned_views
                .push(view.current_conditioned_view().clone());
            if issue_invalid_message {
                self.invalid_message_move_ordinal = Some(view.verifier_move().ordinal);
                wrong_shape_adversarial_message(view.verifier_move())
            } else {
                selected_adversarial_message(view.verifier_move())
            }
        }
    }

    #[derive(Default)]
    struct InvalidOnceAtPreRole18Verifier {
        refused_move_ordinals: Vec<u32>,
    }

    impl CompactAdaptiveVerifier for InvalidOnceAtPreRole18Verifier {
        fn choose_message(
            &mut self,
            view: CompactAdaptiveVerifierView<'_>,
        ) -> DecodedFixedUniformVerifierMessage {
            let move_ordinal = view.verifier_move().ordinal;
            if move_ordinal == 52 && !self.refused_move_ordinals.contains(&move_ordinal) {
                self.refused_move_ordinals.push(move_ordinal);
                wrong_shape_adversarial_message(view.verifier_move())
            } else {
                selected_adversarial_message(view.verifier_move())
            }
        }
    }

    fn selected_simulator(
        private_key: [u8; 64],
    ) -> (
        std::rc::Rc<super::super::compact_proof_contract::CompactPublicKeyProofContract>,
        CompactMaskingCoefficientMapCertificate,
    ) {
        let contract = selected_compact_public_key_proof_contract().expect("selected contract");
        let maps = derive_compact_masking_coefficient_map_certificate(contract.verifier_inputs())
            .expect("selected coefficient maps");
        let _ = private_key;
        (contract, maps)
    }

    fn selected_verified_public_input(
        contract: &super::super::compact_proof_contract::CompactPublicKeyProofContract,
        first_value: ProofBaseFieldElement,
        check_wrong_relation_binding: bool,
    ) -> VerifiedCompactPublicInputTransport {
        let inputs = contract.verifier_inputs();
        let bindings = CompactPublicInputBindings::new(
            Hash512::from_bytes([0x21; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x23; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes(inputs.relation.relation_plan_variant_hash()),
        );
        let field_element_count =
            usize::try_from(inputs.public_input_wire_geometry.field_element_count())
                .expect("selected public-input count fits memory");
        let mut field_elements = vec![ProofBaseFieldElement::ZERO; field_element_count];
        field_elements[0] = first_value;
        if check_wrong_relation_binding {
            let mut wrong_relation_hash = inputs.relation.relation_plan_variant_hash();
            wrong_relation_hash[0] ^= 1;
            let wrong_bindings = CompactPublicInputBindings::new(
                Hash512::from_bytes([0x21; Hash512::BYTE_LENGTH]),
                Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
                Hash512::from_bytes([0x23; Hash512::BYTE_LENGTH]),
                Hash512::from_bytes(wrong_relation_hash),
            );
            let wrong_bytes = encode_compact_public_input(
                inputs.public_input_wire_geometry,
                wrong_bindings,
                &field_elements,
            )
            .expect("wrong-relation public input remains canonically encoded");
            assert_eq!(
                validate_selected_compact_public_input_transport(
                    wrong_bindings,
                    wrong_bytes.into_boxed_slice(),
                )
                .err(),
                Some(CompactPublicKeyTransportError::InvalidResponseRegistry)
            );
        }
        let canonical_bytes = encode_compact_public_input(
            inputs.public_input_wire_geometry,
            bindings,
            &field_elements,
        )
        .expect("selected public input encodes");
        drop(field_elements);
        validate_selected_compact_public_input_transport(
            bindings,
            canonical_bytes.into_boxed_slice(),
        )
        .expect("strict selected public-input transport verifies")
    }

    fn advance_to_move_count(
        simulator: &mut CompactAdaptiveMaskingSimulator<'_>,
        verifier: &mut impl CompactAdaptiveVerifier,
        target_move_count: usize,
    ) {
        while simulator.attempt.moves.len() < target_move_count {
            simulator
                .advance(verifier)
                .expect("ordinary verifier move advances before role 18");
        }
        assert_eq!(simulator.attempt.moves.len(), target_move_count);
    }

    fn derive_role18_authorization(
        simulator: &CompactAdaptiveMaskingSimulator<'_>,
    ) -> (CompactFactorOneCarriedCovector, usize) {
        let mut derivation = simulator
            .begin_role18_covector_derivation()
            .expect("role-18 semantic derivation begins from simulator prefix");
        let mut work_boundary_count = 0_usize;
        loop {
            match derivation
                .advance(65_536)
                .expect("bounded role-18 semantic work advances")
            {
                CompactFactorOnePublicCovectorPoll::WorkCompleted {
                    completed_work_unit_count,
                } => {
                    assert!((1..=65_536).contains(&completed_work_unit_count));
                    work_boundary_count += 1;
                }
                CompactFactorOnePublicCovectorPoll::Complete {
                    completed_work_unit_count,
                    authorization,
                } => {
                    assert!((1..=65_536).contains(&completed_work_unit_count));
                    work_boundary_count += 1;
                    return (*authorization, work_boundary_count);
                }
            }
        }
    }

    fn derive_role18_authorization_with_varied_budgets(
        simulator: &CompactAdaptiveMaskingSimulator<'_>,
        work_budgets: &[u64],
    ) -> (CompactFactorOneCarriedCovector, usize) {
        assert!(!work_budgets.is_empty());
        assert!(work_budgets.iter().all(|budget| *budget > 0));
        let mut derivation = simulator
            .begin_role18_covector_derivation()
            .expect("role-18 semantic derivation begins from simulator prefix");
        assert!(matches!(
            derivation.advance(0),
            Err(CompactFactorOnePublicCovectorError::InvalidCovector)
        ));
        let mut poll_ordinal = 0_usize;
        let authorization = loop {
            let work_budget = work_budgets[poll_ordinal % work_budgets.len()];
            poll_ordinal += 1;
            match derivation
                .advance(work_budget)
                .expect("varied-budget role-18 semantic work advances")
            {
                CompactFactorOnePublicCovectorPoll::WorkCompleted {
                    completed_work_unit_count,
                } => {
                    assert!((1..=work_budget).contains(&completed_work_unit_count));
                }
                CompactFactorOnePublicCovectorPoll::Complete {
                    completed_work_unit_count,
                    authorization,
                } => {
                    assert!((1..=work_budget).contains(&completed_work_unit_count));
                    break *authorization;
                }
            }
        };
        assert!(matches!(
            derivation.advance(1),
            Err(CompactFactorOnePublicCovectorError::InvalidCovector)
        ));
        (authorization, poll_ordinal)
    }

    fn derive_role18_authorization_with_whole_operation_reference(
        simulator: &CompactAdaptiveMaskingSimulator<'_>,
    ) -> CompactFactorOneCarriedCovector {
        let prefix = simulator
            .mint_semantic_prefix()
            .expect("the role-18 reference prefix is valid");
        simulator
            .public_covector_authority
            .as_ref()
            .expect("the simulator owns its public-covector authority")
            .begin_prefix_derivation(prefix)
            .expect("the whole-operation reference derivation begins")
            .finish_with_whole_operation_reference()
            .expect("the whole-operation reference derivation completes")
    }

    fn role18_covector_canonical_bytes(authorization: &CompactFactorOneCarriedCovector) -> Vec<u8> {
        authorization
            .coefficients()
            .expect("the role-18 authorization remains pending")
            .iter()
            .flat_map(|coefficient| {
                compact_challenge_to_production(*coefficient)
                    .expect("the role-18 coefficient is canonical")
                    .canonical_coordinates()
                    .into_iter()
                    .flat_map(u64::to_le_bytes)
            })
            .collect()
    }

    fn advance_to_terminal_prefix(
        simulator: &mut CompactAdaptiveMaskingSimulator<'_>,
        verifier: &mut impl CompactAdaptiveVerifier,
    ) {
        while simulator.attempt.moves.len() < simulator.verifier_inputs.verifier_moves.len() {
            advance_next_move_with_role18(simulator, verifier);
        }
    }

    fn advance_next_move_with_role18(
        simulator: &mut CompactAdaptiveMaskingSimulator<'_>,
        verifier: &mut impl CompactAdaptiveVerifier,
    ) -> u32 {
        let next_move_ordinal = simulator.attempt.moves.len();
        let role18_authorization_required = simulator
            .replay_entropy_authority()
            .expect("entropy authority replays the current simulator prefix")
            .next_base_claim_requirement()
            .expect("the next response requirement is canonical")
            .is_some();
        if role18_authorization_required {
            let (mut authorization, _) = derive_role18_authorization(simulator);
            let move_ordinal = simulator
                .advance_role18(verifier, &mut authorization)
                .unwrap_or_else(|error| {
                    panic!(
                        "opaque role-18 authorization advances move {next_move_ordinal}: {error:?}"
                    )
                });
            assert_eq!(authorization.epoch(), None);
            move_ordinal
        } else {
            simulator.advance(verifier).unwrap_or_else(|error| {
                panic!("ordinary verifier move {next_move_ordinal} advances: {error:?}")
            })
        }
    }

    fn programmed_commitment_count(simulator: &CompactAdaptiveMaskingSimulator<'_>) -> usize {
        simulator
            .attempt
            .moves
            .iter()
            .map(|record| record.conditioned_view.new_construction_commitments.len())
            .sum()
    }

    #[test]
    fn fresh_source_mirror_prefix_uses_message_then_randomness() {
        let (contract, maps) = selected_simulator([0x6a; 64]);
        let certificate =
            selected_test_compact_masking_entropy_certificate(&contract.verifier_inputs(), &maps)
                .expect("selected entropy certificate");
        let epoch = 1;
        let message_step = certificate
            .steps()
            .iter()
            .find(|step| {
                step.kind() == CompactMaskingDisclosureKind::BaseBlindedSourceMessage { epoch }
            })
            .expect("source message reveal")
            .clone();
        let randomness_step = certificate
            .steps()
            .iter()
            .find(|step| {
                step.kind() == CompactMaskingDisclosureKind::BaseBlindedSourceRandomness { epoch }
            })
            .expect("source randomness reveal")
            .clone();
        let message_value = CompactChallengeField::from_u64(41);
        let randomness_value = CompactChallengeField::from_u64(73);
        let message = CompactIdealDisclosure {
            field_values: vec![
                message_value;
                usize::try_from(message_step.output_coordinate_count())
                    .expect("message geometry fits")
            ],
            entropy_step: message_step,
            coin_coordinate_start: 0,
        };
        let randomness = CompactIdealDisclosure {
            field_values: vec![
                randomness_value;
                usize::try_from(randomness_step.output_coordinate_count())
                    .expect("randomness geometry fits")
            ],
            entropy_step: randomness_step,
            coin_coordinate_start: 0,
        };

        // Input storage order is irrelevant: the retained coefficient vector
        // follows the certified affine-mirror geometry.
        let reversed_disclosures = [randomness.clone(), message.clone()];
        let retained = retained_mirror_coefficients(
            CompactMaskingDisclosureKind::FreshSourceQueries { epoch },
            &[],
            &[],
            &reversed_disclosures,
        )
        .expect("complete source mirror prefix")
        .expect("source queries require mirror coefficients");
        assert_eq!(
            retained.len(),
            message.field_values.len() + randomness.field_values.len()
        );
        assert!(
            retained[..message.field_values.len()]
                .iter()
                .all(|value| *value == message_value)
        );
        assert!(
            retained[message.field_values.len()..]
                .iter()
                .all(|value| *value == randomness_value)
        );

        let duplicate_message = [randomness.clone(), message.clone(), message.clone()];
        assert_eq!(
            retained_mirror_coefficients(
                CompactMaskingDisclosureKind::FreshSourceQueries { epoch },
                &[],
                &[],
                &duplicate_message,
            ),
            Err(CompactMaskingSimulatorError::WrongTranscript)
        );
        let mut malformed_message = message;
        malformed_message.field_values.pop();
        assert_eq!(
            retained_mirror_coefficients(
                CompactMaskingDisclosureKind::FreshSourceQueries { epoch },
                &[],
                &[],
                &[randomness, malformed_message],
            ),
            Err(CompactMaskingSimulatorError::WrongTranscript)
        );
    }

    #[test]
    fn checkpoint_restore_accepts_exact_prefix_and_fails_closed_on_wrong_key_or_cursor() {
        let private_key = [0x6b; 64];
        let (contract, maps) = selected_simulator(private_key);
        let mut simulator = CompactAdaptiveMaskingSimulator::new(
            contract.verifier_inputs(),
            &maps,
            [0x51; 32],
            [0x61; 64],
            private_key,
        )
        .expect("selected simulator");
        let initial_checkpoint = simulator.checkpoint().expect("initial checkpoint");
        let restored_initial = CompactAdaptiveMaskingSimulator::restore(
            contract.verifier_inputs(),
            &maps,
            initial_checkpoint.clone(),
            private_key,
        )
        .expect("the exact empty prefix restores");
        assert_eq!(
            restored_initial
                .checkpoint()
                .expect("the restored empty prefix authenticates"),
            initial_checkpoint
        );
        assert_eq!(
            CompactAdaptiveMaskingSimulator::restore(
                contract.verifier_inputs(),
                &maps,
                initial_checkpoint.clone(),
                [0x7c; 64],
            )
            .err(),
            Some(CompactMaskingSimulatorError::WrongCheckpoint)
        );

        let mut altered_cursor = initial_checkpoint;
        altered_cursor.attempt.next_coin_coordinate = 1;
        assert_eq!(
            CompactAdaptiveMaskingSimulator::restore(
                contract.verifier_inputs(),
                &maps,
                altered_cursor,
                private_key,
            )
            .err(),
            Some(CompactMaskingSimulatorError::WrongTranscript)
        );

        assert_eq!(simulator.attempt.next_coin_coordinate, 0);
        simulator
            .advance(&mut SelectedAdversarialVerifier)
            .expect("the first ordinary move advances");
        let first_move_checkpoint = simulator
            .checkpoint()
            .expect("the first completed move authenticates");
        let restored_first_move = CompactAdaptiveMaskingSimulator::restore(
            contract.verifier_inputs(),
            &maps,
            first_move_checkpoint.clone(),
            private_key,
        )
        .expect("the exact one-move prefix restores before later commitments exist");
        assert_eq!(
            restored_first_move
                .checkpoint()
                .expect("the restored one-move prefix authenticates"),
            first_move_checkpoint
        );
        assert_eq!(
            simulator.finish().err(),
            Some(CompactMaskingSimulatorError::SimulationNotActive)
        );
    }

    #[test]
    fn invalid_message_retry_replays_the_staged_view_and_commits_it_once() {
        let private_key = [0x6c; 64];
        let (contract, maps) = selected_simulator(private_key);
        let mut simulator = CompactAdaptiveMaskingSimulator::new(
            contract.verifier_inputs(),
            &maps,
            [0x53; 32],
            [0x63; 64],
            private_key,
        )
        .expect("selected simulator");
        let mut verifier = InvalidThenValidVerifier::default();

        let (attempt_before_invalid_message, checkpoint_before_invalid_message) = loop {
            let staged_attempt = simulator.attempt.clone();
            let staged_checkpoint = simulator.checkpoint().expect("prefix checkpoint");
            match simulator.advance(&mut verifier) {
                Ok(_) => {}
                Err(CompactMaskingSimulatorError::InvalidVerifierMessage) => {
                    break (staged_attempt, staged_checkpoint);
                }
                Err(error) => panic!("unexpected simulator refusal before retry: {error:?}"),
            }
        };
        assert_eq!(simulator.attempt, attempt_before_invalid_message);
        assert_eq!(
            simulator.checkpoint().expect("checkpoint after refusal"),
            checkpoint_before_invalid_message
        );
        let refused_view = verifier
            .exposed_conditioned_views
            .last()
            .expect("the invalid message observed one conditioned view")
            .clone();
        assert!(!refused_view.disclosures.is_empty());
        assert!(!refused_view.new_construction_commitments.is_empty());

        let refused_move_ordinal = verifier
            .invalid_message_move_ordinal
            .expect("one invalid message was issued");
        let view_count_before_retry = verifier.exposed_conditioned_views.len();
        assert_eq!(simulator.advance(&mut verifier), Ok(refused_move_ordinal));
        assert_eq!(
            verifier.exposed_conditioned_views.len(),
            view_count_before_retry + 1
        );
        assert_eq!(
            verifier.exposed_conditioned_views.last(),
            Some(&refused_view)
        );
        assert_eq!(
            simulator.attempt.moves.len(),
            attempt_before_invalid_message.moves.len() + 1
        );
        assert!(
            simulator
                .attempt
                .moves
                .starts_with(&attempt_before_invalid_message.moves)
        );
        let committed_move = simulator
            .attempt
            .moves
            .last()
            .expect("the retried move committed");
        assert_eq!(committed_move.conditioned_view, refused_view);
        assert_eq!(
            simulator
                .attempt
                .moves
                .iter()
                .map(|record| { record.conditioned_view.new_construction_commitments.len() })
                .sum::<usize>(),
            attempt_before_invalid_message
                .moves
                .iter()
                .map(|record| { record.conditioned_view.new_construction_commitments.len() })
                .sum::<usize>()
                + committed_move
                    .conditioned_view
                    .new_construction_commitments
                    .len()
        );
        let committed_coin_count = committed_move
            .conditioned_view
            .disclosures
            .iter()
            .chain(&committed_move.post_message_disclosures)
            .map(|disclosure| disclosure.entropy_step.conditional_rank())
            .sum::<u64>();
        assert_eq!(
            simulator.attempt.next_coin_coordinate,
            attempt_before_invalid_message.next_coin_coordinate + committed_coin_count
        );
    }

    #[test]
    fn rewind_authenticates_oracle_key_and_exposed_prefix() {
        let (contract, maps) = selected_simulator([0x6d; 64]);
        let mut simulator = CompactAdaptiveMaskingSimulator::new(
            contract.verifier_inputs(),
            &maps,
            [0x52; 32],
            [0x62; 64],
            [0x6d; 64],
        )
        .expect("selected simulator");
        let foreign_checkpoint = CompactAdaptiveMaskingSimulator::new(
            contract.verifier_inputs(),
            &maps,
            [0x52; 32],
            [0x62; 64],
            [0x7d; 64],
        )
        .expect("foreign-key simulator")
        .checkpoint()
        .expect("foreign checkpoint");
        assert_eq!(
            simulator
                .rewind_security_game_suffix(foreign_checkpoint)
                .err(),
            Some(CompactMaskingSimulatorError::WrongCheckpoint)
        );

        let mut altered_prefix = simulator.checkpoint().expect("local checkpoint");
        altered_prefix.exposed_prefix_binding[0] ^= 1;
        assert_eq!(
            simulator.rewind_security_game_suffix(altered_prefix).err(),
            Some(CompactMaskingSimulatorError::WrongCheckpoint)
        );
        assert_eq!(simulator.attempt.reset_ordinal, 0);
        assert_eq!(simulator.attempt.next_coin_coordinate, 0);
        assert!(simulator.retired_coin_ranges.is_empty());
        assert!(simulator.retired_commitment_handles.is_empty());
    }

    #[test]
    fn semantic_base_claim_move_is_gated_without_an_opaque_prefix_token() {
        let private_key = [0x7d; 64];
        let (contract, maps) = selected_simulator(private_key);
        let mut simulator = CompactAdaptiveMaskingSimulator::new(
            contract.verifier_inputs(),
            &maps,
            [0x71; 32],
            [0x81; 64],
            private_key,
        )
        .expect("selected simulator");
        let mut verifier = SelectedAdversarialVerifier;
        let refusal = loop {
            match simulator.advance(&mut verifier) {
                Ok(_) => {}
                Err(error) => break error,
            }
        };
        assert_eq!(
            refusal,
            CompactMaskingSimulatorError::Role18AuthorizationRequired
        );
        assert!(
            simulator
                .replay_entropy_authority()
                .expect("authority replays to gated move")
                .next_base_claim_requirement()
                .expect("requirement query")
                .is_some()
        );
    }

    #[test]
    #[ignore = "guarded selected pre-challenge and main role-18 covector equivalence"]
    fn heavy_rust_kernel_selected_role18_bounded_covectors_match_whole_operation_reference() {
        let private_key = [0x8c; 64];
        let (contract, maps) = selected_simulator(private_key);
        let verified_public_input =
            selected_verified_public_input(&contract, ProofBaseFieldElement::ZERO, false);
        let public_covector_authority =
            CompactFactorOnePublicCovectorAuthority::from_verified_public_input(
                &verified_public_input,
            )
            .expect("selected public-input authority");
        let mut simulator = CompactAdaptiveMaskingSimulator::new_with_public_covector_authority(
            contract.verifier_inputs(),
            &maps,
            [0x71; 32],
            [0x81; 64],
            private_key,
            public_covector_authority,
        )
        .expect("authority-bound selected simulator");
        let role18_moves = contract
            .verifier_inputs()
            .verifier_moves
            .iter()
            .filter_map(|verifier_move| {
                verifier_move
                    .role_coordinates
                    .iter()
                    .find(|role| role.role_tag == 10)
                    .map(|role| (verifier_move.ordinal, role.epoch))
            })
            .collect::<Vec<_>>();
        assert_eq!(role18_moves.len(), 2);
        assert_eq!(
            role18_moves
                .iter()
                .map(|(_, epoch)| *epoch)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );

        let mut selected_verifier = SelectedAdversarialVerifier;
        for (move_ordinal, epoch) in role18_moves {
            advance_to_move_count(
                &mut simulator,
                &mut selected_verifier,
                usize::try_from(move_ordinal).expect("selected role-18 ordinal fits usize"),
            );
            assert_eq!(
                simulator.advance(&mut selected_verifier),
                Err(CompactMaskingSimulatorError::Role18AuthorizationRequired)
            );

            let valid_prefix = simulator
                .mint_semantic_prefix()
                .expect("selected role-18 semantic prefix");
            let wrong_epoch = if epoch == 1 { 2 } else { 1 };
            let wrong_epoch_prefix = CompactMaskingSemanticPrefix::from_validated_transcript(
                valid_prefix.attempt_identity(),
                valid_prefix.verifier_move_ordinal(),
                wrong_epoch,
                valid_prefix.contract_source_hash(),
                valid_prefix
                    .canonical_exposed_move_prefix()
                    .to_vec()
                    .into_boxed_slice(),
                valid_prefix
                    .completed_messages()
                    .to_vec()
                    .into_boxed_slice(),
            )
            .expect("the wrong epoch remains chronologically encodable");
            assert!(matches!(
                simulator
                    .public_covector_authority
                    .as_ref()
                    .expect("selected public-covector authority")
                    .begin_prefix_derivation(wrong_epoch_prefix),
                Err(CompactFactorOnePublicCovectorError::InvalidVerifierPrefix)
            ));

            let mut premature_derivation = simulator
                .begin_role18_covector_derivation()
                .expect("selected role-18 premature derivation begins");
            assert!(matches!(
                premature_derivation.advance(1),
                Ok(CompactFactorOnePublicCovectorPoll::WorkCompleted {
                    completed_work_unit_count: 1
                })
            ));

            let reference_authorization =
                derive_role18_authorization_with_whole_operation_reference(&simulator);
            let (mut bounded_authorization, poll_count) =
                derive_role18_authorization_with_varied_budgets(&simulator, &[1, 7, 257, 8_192]);
            assert!(poll_count > 1);
            assert_eq!(bounded_authorization.epoch(), Some(epoch));
            assert_eq!(
                role18_covector_canonical_bytes(&bounded_authorization),
                role18_covector_canonical_bytes(&reference_authorization),
                "bounded epoch-{epoch} covector bytes diverged from the prior whole-operation replay"
            );
            assert_eq!(
                simulator.advance_role18(&mut selected_verifier, &mut bounded_authorization),
                Ok(move_ordinal)
            );
            assert_eq!(bounded_authorization.epoch(), None);
        }
    }

    #[test]
    #[ignore = "guarded selected pre-challenge role-18 public-covector lifecycle"]
    fn heavy_rust_kernel_selected_pre_role18_covector_is_prefix_bound_transactional_and_one_shot() {
        const PRE_ROLE18_MOVE_ORDINAL: u32 = 52;
        const PRE_ROLE18_COEFFICIENT_COUNT: usize = 1_292;

        let private_key = [0x8d; 64];
        let attempt_identifier = [0x72; 32];
        let initial_prefix_binding = [0x82; 64];
        let (contract, maps) = selected_simulator(private_key);
        let verified_public_input =
            selected_verified_public_input(&contract, ProofBaseFieldElement::ZERO, true);

        let prefix_a_authority =
            CompactFactorOnePublicCovectorAuthority::from_verified_public_input(
                &verified_public_input,
            )
            .expect("first selected public-input authority");
        let mut prefix_a = CompactAdaptiveMaskingSimulator::new_with_public_covector_authority(
            contract.verifier_inputs(),
            &maps,
            attempt_identifier,
            initial_prefix_binding,
            private_key,
            prefix_a_authority,
        )
        .expect("first authority-bound simulator");
        let mut selected_verifier = SelectedAdversarialVerifier;
        advance_to_move_count(
            &mut prefix_a,
            &mut selected_verifier,
            usize::try_from(PRE_ROLE18_MOVE_ORDINAL).expect("selected ordinal fits"),
        );
        assert_eq!(
            prefix_a.advance(&mut selected_verifier),
            Err(CompactMaskingSimulatorError::Role18AuthorizationRequired)
        );
        let (mut prefix_a_authorization, prefix_a_work_boundary_count) =
            derive_role18_authorization(&prefix_a);
        assert!(prefix_a_work_boundary_count > 0);
        assert_eq!(prefix_a_authorization.epoch(), Some(1));
        assert_eq!(
            prefix_a_authorization
                .coefficients()
                .expect("pre authorization is pending")
                .len(),
            PRE_ROLE18_COEFFICIENT_COUNT
        );
        drop(prefix_a);

        let prefix_b_authority =
            CompactFactorOnePublicCovectorAuthority::from_verified_public_input(
                &verified_public_input,
            )
            .expect("second selected public-input authority");
        let mut simulator = CompactAdaptiveMaskingSimulator::new_with_public_covector_authority(
            contract.verifier_inputs(),
            &maps,
            attempt_identifier,
            initial_prefix_binding,
            private_key,
            prefix_b_authority,
        )
        .expect("second authority-bound simulator");
        let mut prefix_variant_verifier = PrefixVariantVerifier;
        advance_to_move_count(
            &mut simulator,
            &mut prefix_variant_verifier,
            usize::try_from(PRE_ROLE18_MOVE_ORDINAL - 1).expect("selected ordinal fits"),
        );
        let rewind_checkpoint = simulator
            .checkpoint()
            .expect("checkpoint immediately before the pre-role18 prefix suffix");
        assert_eq!(
            simulator.advance(&mut prefix_variant_verifier),
            Ok(PRE_ROLE18_MOVE_ORDINAL - 1)
        );
        assert_eq!(
            simulator.advance(&mut prefix_variant_verifier),
            Err(CompactMaskingSimulatorError::Role18AuthorizationRequired)
        );

        let before_prefix_substitution = simulator
            .checkpoint()
            .expect("prefix-substitution checkpoint");
        assert_eq!(
            simulator.advance_role18(&mut prefix_variant_verifier, &mut prefix_a_authorization,),
            Err(CompactMaskingSimulatorError::InvalidRole18Authorization)
        );
        assert_eq!(
            simulator
                .checkpoint()
                .expect("prefix substitution does not mutate simulator"),
            before_prefix_substitution
        );
        assert_eq!(prefix_a_authorization.epoch(), Some(1));
        drop(before_prefix_substitution);
        drop(prefix_a_authorization);

        let (mut stale_authorization, stale_work_boundary_count) =
            derive_role18_authorization(&simulator);
        assert!(stale_work_boundary_count > 0);
        let reset_ordinal_before_rewind = simulator.attempt.reset_ordinal;
        simulator
            .rewind_security_game_suffix(rewind_checkpoint)
            .expect("authenticated suffix rewind");
        assert_eq!(
            simulator.attempt.reset_ordinal,
            reset_ordinal_before_rewind + 1
        );
        assert_eq!(
            simulator.attempt.moves.len(),
            usize::try_from(PRE_ROLE18_MOVE_ORDINAL - 1).expect("selected ordinal fits")
        );
        assert_eq!(
            simulator.advance(&mut prefix_variant_verifier),
            Ok(PRE_ROLE18_MOVE_ORDINAL - 1)
        );
        assert_eq!(
            simulator.advance(&mut prefix_variant_verifier),
            Err(CompactMaskingSimulatorError::Role18AuthorizationRequired)
        );
        assert_eq!(
            simulator.advance_role18(&mut prefix_variant_verifier, &mut stale_authorization),
            Err(CompactMaskingSimulatorError::InvalidRole18Authorization)
        );
        assert_eq!(stale_authorization.epoch(), Some(1));
        drop(stale_authorization);

        let (mut pre_authorization, pre_work_boundary_count) =
            derive_role18_authorization(&simulator);
        assert!(pre_work_boundary_count > 0);
        assert_eq!(pre_authorization.epoch(), Some(1));
        assert_eq!(
            pre_authorization
                .coefficients()
                .expect("reminted pre authorization is pending")
                .len(),
            PRE_ROLE18_COEFFICIENT_COUNT
        );
        let mut retry_verifier = InvalidOnceAtPreRole18Verifier::default();
        let before_invalid_pre_message = simulator
            .checkpoint()
            .expect("checkpoint before invalid pre-role18 message");
        assert_eq!(
            simulator.advance_role18(&mut retry_verifier, &mut pre_authorization),
            Err(CompactMaskingSimulatorError::InvalidVerifierMessage)
        );
        assert_eq!(
            simulator
                .checkpoint()
                .expect("invalid pre-role18 message rolls back"),
            before_invalid_pre_message
        );
        assert_eq!(pre_authorization.epoch(), Some(1));
        drop(before_invalid_pre_message);
        assert_eq!(
            simulator.advance_role18(&mut retry_verifier, &mut pre_authorization),
            Ok(PRE_ROLE18_MOVE_ORDINAL)
        );
        assert_eq!(pre_authorization.epoch(), None);
        let after_pre_role18 = simulator
            .checkpoint()
            .expect("authority-bound checkpoint after pre role18");
        assert_eq!(
            simulator.advance_role18(&mut retry_verifier, &mut pre_authorization),
            Err(CompactMaskingSimulatorError::InvalidRole18Authorization)
        );
        assert_eq!(
            simulator
                .checkpoint()
                .expect("consumed pre authorization cannot mutate next move"),
            after_pre_role18
        );

        assert_eq!(
            CompactAdaptiveMaskingSimulator::restore(
                contract.verifier_inputs(),
                &maps,
                after_pre_role18.clone(),
                private_key,
            )
            .err(),
            Some(CompactMaskingSimulatorError::WrongCheckpoint)
        );
        let restored_authority =
            CompactFactorOnePublicCovectorAuthority::from_verified_public_input(
                &verified_public_input,
            )
            .expect("same-input restore authority");
        let restored = CompactAdaptiveMaskingSimulator::restore_with_public_covector_authority(
            contract.verifier_inputs(),
            &maps,
            after_pre_role18.clone(),
            private_key,
            restored_authority,
        )
        .expect("same-input authority restores checkpoint");
        assert_eq!(
            restored
                .checkpoint()
                .expect("restored checkpoint authenticates"),
            after_pre_role18
        );
        drop(restored);

        let substituted_public_input =
            selected_verified_public_input(&contract, ProofBaseFieldElement::ONE, false);
        let substituted_authority =
            CompactFactorOnePublicCovectorAuthority::from_verified_public_input(
                &substituted_public_input,
            )
            .expect("substituted canonical public input has its own authority");
        assert_eq!(
            CompactAdaptiveMaskingSimulator::restore_with_public_covector_authority(
                contract.verifier_inputs(),
                &maps,
                after_pre_role18,
                private_key,
                substituted_authority,
            )
            .err(),
            Some(CompactMaskingSimulatorError::WrongCheckpoint)
        );
        drop(substituted_public_input);
    }

    #[test]
    #[ignore = "guarded selected construction masking theorem and simulator lifecycle"]
    fn heavy_rust_kernel_selected_masking_simulator_terminal_authenticates_restore_and_rewind() {
        let private_key = [0x9d; 64];
        let (contract, maps) = selected_simulator(private_key);
        let verified_public_input =
            selected_verified_public_input(&contract, ProofBaseFieldElement::ZERO, false);
        let public_covector_authority =
            CompactFactorOnePublicCovectorAuthority::from_verified_public_input(
                &verified_public_input,
            )
            .expect("selected public-input authority");
        let expected_public_input_binding = public_covector_authority.public_input_binding();
        let mut simulator = CompactAdaptiveMaskingSimulator::new_with_public_covector_authority(
            contract.verifier_inputs(),
            &maps,
            [0x73; 32],
            [0x83; 64],
            private_key,
            public_covector_authority,
        )
        .expect("authority-bound selected simulator");
        let mut verifier = SelectedAdversarialVerifier;
        simulator
            .advance(&mut verifier)
            .expect("first ordinary move advances");
        let nonterminal_checkpoint = simulator
            .checkpoint()
            .expect("nonempty nonterminal checkpoint");

        let continuation_authority =
            CompactFactorOnePublicCovectorAuthority::from_verified_public_input(
                &verified_public_input,
            )
            .expect("same-input continuation authority");
        let mut simulator =
            CompactAdaptiveMaskingSimulator::restore_with_public_covector_authority(
                contract.verifier_inputs(),
                &maps,
                nonterminal_checkpoint.clone(),
                private_key,
                continuation_authority,
            )
            .expect("same-key nonterminal continuation restores");
        assert_eq!(
            simulator
                .checkpoint()
                .expect("restored nonterminal checkpoint authenticates"),
            nonterminal_checkpoint
        );

        let abandoned_identity = simulator.attempt_identity();
        let abandoned_coin_start = simulator.attempt.next_coin_coordinate;
        let abandoned_commitment_start = programmed_commitment_count(&simulator);
        while simulator.attempt.next_coin_coordinate == abandoned_coin_start
            || programmed_commitment_count(&simulator) == abandoned_commitment_start
        {
            advance_next_move_with_role18(&mut simulator, &mut verifier);
        }
        let abandoned_coin_end = simulator.attempt.next_coin_coordinate;
        let abandoned_handles = simulator.attempt.moves
            [nonterminal_checkpoint.attempt.moves.len()..]
            .iter()
            .flat_map(|record| &record.conditioned_view.new_construction_commitments)
            .map(CompactConstructionCommitmentProgram::handle)
            .collect::<Vec<_>>();
        assert!(!abandoned_handles.is_empty());
        let reset_ordinal = simulator.attempt.reset_ordinal;
        simulator
            .rewind_security_game_suffix(nonterminal_checkpoint.clone())
            .expect("authenticated nonempty suffix rewinds");
        assert_eq!(simulator.attempt.reset_ordinal, reset_ordinal + 1);
        assert!(simulator.retired_coin_ranges.iter().any(|range| {
            range.identity == abandoned_identity
                && range.start == abandoned_coin_start
                && range.end == abandoned_coin_end
        }));
        assert!(
            abandoned_handles
                .iter()
                .all(|handle| simulator.retired_commitment_handles.contains(handle))
        );

        let fresh_completion_authority =
            CompactFactorOnePublicCovectorAuthority::from_verified_public_input(
                &verified_public_input,
            )
            .expect("fresh single-attempt completion authority");
        let mut simulator =
            CompactAdaptiveMaskingSimulator::restore_with_public_covector_authority(
                contract.verifier_inputs(),
                &maps,
                nonterminal_checkpoint,
                private_key,
                fresh_completion_authority,
            )
            .expect("fresh single-attempt branch restores");
        advance_to_terminal_prefix(&mut simulator, &mut verifier);
        assert_eq!(
            simulator.attempt.moves.len(),
            simulator.verifier_inputs.verifier_moves.len()
        );
        let (terminal_checkpoint, theorem) = simulator
            .finish_construction_masking_theorem()
            .expect("fresh terminal simulator derives the construction masking theorem");
        assert_eq!(theorem.public_input_binding, expected_public_input_binding);
        assert_eq!(theorem.verifier_move_count, 82);
        assert_eq!(theorem.construction_commitment_count, 45);
        assert_eq!(theorem.private_coordinate_count, 230_488);
        assert!(theorem.joint_disclosure_rank < 230_324);
        assert!(theorem.residual_fiber_dimension > 164);
        assert_eq!(
            theorem.joint_disclosure_rank + theorem.residual_fiber_dimension,
            theorem.private_coordinate_count
        );
        assert!(theorem.shared_cross_epoch_query_overlap > 0);
        assert!(theorem.exposed_output_coordinate_count >= theorem.joint_disclosure_rank);
        assert_eq!(theorem.exact_statistical_distance_numerator, 0);
        assert_eq!(theorem.exact_statistical_distance_denominator, 1);
        for experiment in [
            CompactAdaptiveMaskingExperiment::RealCanonicalConstruction,
            CompactAdaptiveMaskingExperiment::WitnessFreeIdealUniform,
        ] {
            assert_eq!(
                theorem
                    .conditional_laws
                    .iter()
                    .map(|law| law.probability_exponent(experiment))
                    .sum::<u64>(),
                theorem.joint_disclosure_rank
            );
        }
        assert!(
            theorem.applies_to(CompactConstructionMaskingClaimScope::SingleCanonicalProofAttempt)
        );
        for excluded_scope in [
            CompactConstructionMaskingClaimScope::AuthenticatedReset,
            CompactConstructionMaskingClaimScope::ReusedPrivateRandomness,
            CompactConstructionMaskingClaimScope::MultipleProofs,
            CompactConstructionMaskingClaimScope::ProofFamily,
            CompactConstructionMaskingClaimScope::Ceremony,
            CompactConstructionMaskingClaimScope::SharedRandomOracle,
            CompactConstructionMaskingClaimScope::ExplicitlyProgrammableRandomOracle,
            CompactConstructionMaskingClaimScope::QuantumRandomOracleZeroKnowledge,
            CompactConstructionMaskingClaimScope::CanonicalEmittedProofBytes,
        ] {
            assert!(!theorem.applies_to(excluded_scope));
        }
        theorem
            .check()
            .expect("construction masking theorem remains intrinsically bound");

        let mut changed_public_input = theorem.clone();
        changed_public_input.public_input_binding[0] ^= 1;
        assert_eq!(
            changed_public_input.check(),
            Err(CompactMaskingSimulatorError::InvalidConstructionGameLaw)
        );
        let mut changed_ideal_rank = theorem.clone();
        changed_ideal_rank.conditional_laws[0].ideal_uniform_coordinate_count += 1;
        assert_eq!(
            changed_ideal_rank.check(),
            Err(CompactMaskingSimulatorError::InvalidConstructionGameLaw)
        );
        let mut changed_residual_fiber = theorem.clone();
        changed_residual_fiber
            .conditional_laws
            .last_mut()
            .expect("selected law is nonempty")
            .real_fiber_dimension_after += 1;
        assert_eq!(
            changed_residual_fiber.check(),
            Err(CompactMaskingSimulatorError::InvalidConstructionGameLaw)
        );

        let terminal_restore_authority =
            CompactFactorOnePublicCovectorAuthority::from_verified_public_input(
                &verified_public_input,
            )
            .expect("same-input terminal restore authority");
        let restored_terminal =
            CompactAdaptiveMaskingSimulator::restore_with_public_covector_authority(
                contract.verifier_inputs(),
                &maps,
                terminal_checkpoint.clone(),
                private_key,
                terminal_restore_authority,
            )
            .expect("same-key terminal checkpoint restores")
            .finish()
            .expect("restored terminal prefix authenticates");
        assert_eq!(restored_terminal, terminal_checkpoint);

        let mut altered_terminal_cursor = terminal_checkpoint;
        altered_terminal_cursor.attempt.next_coin_coordinate = altered_terminal_cursor
            .attempt
            .next_coin_coordinate
            .checked_add(1)
            .expect("selected terminal coin cursor increments");
        let altered_cursor_authority =
            CompactFactorOnePublicCovectorAuthority::from_verified_public_input(
                &verified_public_input,
            )
            .expect("same-input altered-cursor authority");
        assert_eq!(
            CompactAdaptiveMaskingSimulator::restore_with_public_covector_authority(
                contract.verifier_inputs(),
                &maps,
                altered_terminal_cursor,
                private_key,
                altered_cursor_authority,
            )
            .err(),
            Some(CompactMaskingSimulatorError::WrongTranscript)
        );
    }

    #[test]
    fn exact_goldilocks_sampler_rejects_out_of_range_candidates() {
        let mut draws = vec![Goldilocks::ORDER_U64, 19].into_iter();
        let sampled = sample_exact_goldilocks(|_| draws.next().expect("bounded candidate"))
            .expect("second candidate is accepted");
        assert_eq!(sampled.as_canonical_u64(), 19);
        assert_eq!(
            sample_exact_goldilocks(|_| Goldilocks::ORDER_U64),
            Err(CompactMaskingSimulatorError::IdealOracleRefused)
        );
    }

    #[test]
    fn adversarial_verifier_message_boundary_rejects_invalid_queries() {
        use super::super::fixed_uniform_verifier_message::FixedUniformDistinctQueryGeometry;

        let geometry = FixedUniformVerifierMessageGeometry::new(
            0,
            0,
            0,
            vec![FixedUniformDistinctQueryGeometry::new(8, 2)],
        )
        .expect("valid geometry");
        assert!(
            DecodedFixedUniformVerifierMessage::from_adversarial_values(
                &geometry,
                Vec::new(),
                Vec::new(),
                vec![vec![1, 7]],
            )
            .is_ok()
        );
        assert!(
            DecodedFixedUniformVerifierMessage::from_adversarial_values(
                &geometry,
                Vec::new(),
                Vec::new(),
                vec![vec![1, 1]],
            )
            .is_err()
        );
        assert!(
            DecodedFixedUniformVerifierMessage::from_adversarial_values(
                &geometry,
                Vec::new(),
                Vec::new(),
                vec![vec![1, 8]],
            )
            .is_err()
        );
    }
}
