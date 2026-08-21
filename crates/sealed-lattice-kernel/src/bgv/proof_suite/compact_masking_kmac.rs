//! KMAC coordinates and conditional generator-hybrid accounting for compact masking.
//!
//! The frozen compact-proof contract is the only geometry input. This module
//! derives every construction-hiding field sample and secret Merkle-leaf salt
//! from that contract, maps the two 512-bit seeds to their production private-
//! coin coordinates, and accounts for both the root stream and compact-
//! generation KMAC domains. The resulting conditional accounting keeps
//! computational KMAC advantages symbolic while calculating every statistical
//! or information-theoretic term as an exact rational number.

use num_bigint::BigUint;
use num_traits::One;

use super::compact_cfw_geometry::CompactCfwVerifierConfiguration;
use super::compact_generation_randomness::{
    COMPACT_FIAT_SHAMIR_ROUND_SALT_CUSTOMIZATION, COMPACT_GENERATION_PRIVATE_SEED_COORDINATES,
    COMPACT_PRIVATE_LEAF_SALT_CUSTOMIZATION, COMPACT_PRIVATE_SEED_BYTE_LENGTH,
    COMPACT_WHIR_RANDOM_BLOCK_BYTE_LENGTH, COMPACT_WHIR_RANDOM_CUSTOMIZATION,
};
use super::compact_proof_contract::{
    CompactProofContractError, CompactPublicKeyProofContract, CompactWhirEpochContract,
    CompactWhirFoldContract,
};
#[cfg(test)]
use super::prover::{
    CommonProofPrivateCoinCoordinate, common_proof_private_coin_coordinate_derivation_context_hash,
};
use super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE,
    compact_proof_wire::COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH,
};
use crate::foundation::{
    ACTION_RANDOMNESS_KEY_HIERARCHY_CUSTOMIZATION, ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH,
    ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, DECLARED_ADVERSARIAL_QUERY_BUDGET, Hash512,
    PERSISTENT_PROOF_PREPARATION_CUSTOMIZATION, PERSISTENT_PROOF_WITNESS_ATTEMPT_CUSTOMIZATION,
    PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH, PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION,
    PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH, PROOF_COIN_KEY_BYTE_LENGTH,
    ProofApplicationSlotCeilings, SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
};

const PRIVATE_SAMPLER_CANDIDATE_BYTE_LENGTH: u64 = size_of::<u64>() as u64;
const KMAC256_ATTEMPT_IDENTIFIER_OUTPUT_BIT_LENGTH: u32 = 256;
const KMAC256_BLOCK_OUTPUT_BIT_LENGTH: u32 = 512;
const SHAKE256_IDEAL_QRO_OUTPUT_BIT_LENGTH: u32 = 512;
const KECCAK_F1600_STATE_BIT_LENGTH: u16 = 1_600;
const KECCAK_F1600_PERMUTATION_ROUND_COUNT: u8 = 24;
const SHAKE256_RATE_BIT_LENGTH: u16 = 1_088;
const SHAKE256_CAPACITY_BIT_LENGTH: u16 = 512;
const SHAKE256_RATE_BYTE_LENGTH: u16 = 136;
const SHAKE_DELIMITED_SUFFIX: u8 = 0x1f;
const CSHAKE_DELIMITED_SUFFIX: u8 = 0x04;
const KMAC_FUNCTION_NAME: &[u8] = b"KMAC";
const SELECTED_KMAC_KEY_BIT_LENGTH: u32 = 512;
const SELECTED_KMAC_OUTPUT_BIT_LENGTHS: [u32; 4] = [256, 512, 1_024, 1_536];
/// The exact known terms must stay below the nominal 256-bit computational
/// primitive ceiling. Symbolic KMAC quantum-PRF advantages are deliberately
/// excluded from this numeric gate.
const SELECTED_KNOWN_LOSS_SECURITY_BIT_FLOOR: usize = 256;

/// Exact deployment boundary assumed by the single-proof masking hybrid.
///
/// This is a symbolic assumption, not a producer assertion or a verification
/// capability. It states that one adversary using both deployed interfaces may
/// replace the domain-separated, keyed KMAC256 calls by the random functions
/// named in the three qPRF hops while treating fixed SHAKE256 as the one ideal
/// quantum random oracle used by the later transcript and Merkle reductions.
/// Because both interfaces use Keccak-f[1600], the joint game carries one
/// additional symbolic shared-permutation advantage; domain separation does not
/// make that advantage zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactMaskingJointPrimitiveAssumption {
    FixedKmac256QprfAndFixedShake256IdealQroWithSharedKeccakF1600,
}

impl CompactMaskingJointPrimitiveAssumption {
    const fn identifier(self) -> &'static str {
        match self {
            Self::FixedKmac256QprfAndFixedShake256IdealQroWithSharedKeccakF1600 => {
                "fixed-kmac256-qprf-and-fixed-shake256-ideal-qro-with-shared-keccak-f1600"
            }
        }
    }
}

/// Exact deployed SHAKE256/KMAC256 interface shared by the masking hybrid.
///
/// These are mode and source-correspondence facts, not a security theorem.
/// The test-only joint-interface certificate independently checks the SP
/// 800-185 encodings and the pinned implementations. In particular, this
/// structure does not turn domain separation into independent random oracles
/// and does not assign an advantage to fixed Keccak-f[1600].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactMaskingJointKeccakInterface {
    keccak_state_bit_length: u16,
    keccak_permutation_round_count: u8,
    rate_bit_length: u16,
    capacity_bit_length: u16,
    bytepad_width: u16,
    shake_delimited_suffix: u8,
    shake_fixed_output_bit_length: u32,
    cshake_delimited_suffix: u8,
    kmac_function_name: &'static [u8],
    kmac_uses_fixed_output_mode: bool,
    kmac_key_bit_length: u32,
    kmac_output_bit_lengths: [u32; 4],
    kmac_customization_domains: [&'static [u8]; 7],
    minimum_kmac_call_count: u64,
    maximum_kmac_call_count: u64,
}

impl CompactMaskingJointKeccakInterface {
    fn has_valid_mode_parameters(self) -> bool {
        self.keccak_state_bit_length == KECCAK_F1600_STATE_BIT_LENGTH
            && self.keccak_permutation_round_count == KECCAK_F1600_PERMUTATION_ROUND_COUNT
            && self.rate_bit_length == SHAKE256_RATE_BIT_LENGTH
            && self.capacity_bit_length == SHAKE256_CAPACITY_BIT_LENGTH
            && self.rate_bit_length.checked_add(self.capacity_bit_length)
                == Some(self.keccak_state_bit_length)
            && self.bytepad_width == SHAKE256_RATE_BYTE_LENGTH
            && self.shake_delimited_suffix == SHAKE_DELIMITED_SUFFIX
            && self.shake_fixed_output_bit_length == SHAKE256_IDEAL_QRO_OUTPUT_BIT_LENGTH
            && self.cshake_delimited_suffix == CSHAKE_DELIMITED_SUFFIX
            && self.kmac_function_name == KMAC_FUNCTION_NAME
            && self.kmac_uses_fixed_output_mode
            && self.kmac_key_bit_length == SELECTED_KMAC_KEY_BIT_LENGTH
            && self.kmac_output_bit_lengths == SELECTED_KMAC_OUTPUT_BIT_LENGTHS
            && self.minimum_kmac_call_count > 0
            && self.minimum_kmac_call_count <= self.maximum_kmac_call_count
            && self
                .kmac_customization_domains
                .iter()
                .all(|customization| !customization.is_empty())
            && self
                .kmac_customization_domains
                .iter()
                .enumerate()
                .all(|(index, customization)| {
                    !self.kmac_customization_domains[index + 1..].contains(customization)
                })
    }
}

/// Source requirement and symbolic primitive model carried by the release
/// masking bridge. The builder rederives every numeric term from the selected
/// contract before validation; these labels cannot be supplied by a proof
/// producer and never enter acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactMaskingDeploymentHybridStatement {
    selected_contract_source_hash: Hash512,
    browser_action_root_bit_length: u32,
    quantum_query_budget: u128,
    kmac_qprf_hop_count: u8,
    joint_keccak_interface: CompactMaskingJointKeccakInterface,
    joint_primitive_assumption: CompactMaskingJointPrimitiveAssumption,
}

impl CompactMaskingDeploymentHybridStatement {
    fn validate(
        self,
        expected_contract_source_hash: Hash512,
    ) -> Result<Hash512, CompactMaskingKmacError> {
        if self.browser_action_root_bit_length != bit_length(ACTION_RANDOMNESS_ROOT_BYTE_LENGTH)?
            || self.quantum_query_budget != DECLARED_ADVERSARIAL_QUERY_BUDGET
            || self.selected_contract_source_hash != expected_contract_source_hash
            || self.kmac_qprf_hop_count != 3
            || !self.joint_keccak_interface.has_valid_mode_parameters()
            || self.joint_primitive_assumption.identifier().is_empty()
        {
            return Err(CompactMaskingKmacError::InvalidJointKeccakInterface);
        }
        Ok(self.selected_contract_source_hash)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactMaskingKmacError {
    Contract(CompactProofContractError),
    ArithmeticOverflow,
    InvalidCensus,
    InvalidJointKeccakInterface,
    KnownLossAboveSelectedFloor,
}

impl From<CompactProofContractError> for CompactMaskingKmacError {
    fn from(error: CompactProofContractError) -> Self {
        Self::Contract(error)
    }
}

/// Test-only union multiplicities for the selected compact-proof arithmetic.
/// The multi-proof cases are union bounds only; they do not establish shared-
/// oracle, resettable, or family simulation.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactMaskingKmacUnionScope {
    /// The single-proof masking statement.
    SinglePublicKeyShareProof,
    /// A union over the selected roster's ten public-key-share applications.
    SelectedPublicKeyShareRosterUnion,
    /// A conservative 103-fold repetition of the selected public-key-share
    /// term. This is not an exact census for the other proof families.
    CompletePhysicalProofInventoryMultiplicity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactMaskingKmacCallFamily {
    ActionKeyHierarchy,
    PersistentProofPreparation,
    PersistentWitnessAttempt,
    PrivateSeedBlocks,
    CompactWhirRandomBlocks,
    SecretLeafSalts,
    FiatShamirRoundSalts,
}

/// One fixed KMAC customization/output domain and its per-proof call interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactMaskingKmacCallRow {
    family: CompactMaskingKmacCallFamily,
    customization: &'static [u8],
    key_bit_length: u32,
    output_bit_length: u32,
    minimum_call_count: u64,
    maximum_call_count: u64,
}

/// An exact, deliberately unreduced nonnegative rational upper bound.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactProbabilityUpperBound {
    numerator: BigUint,
    denominator: BigUint,
}

impl ExactProbabilityUpperBound {
    fn zero() -> Self {
        Self {
            numerator: BigUint::default(),
            denominator: BigUint::one(),
        }
    }

    fn new(numerator: BigUint, denominator: BigUint) -> Result<Self, CompactMaskingKmacError> {
        if denominator == BigUint::default() {
            return Err(CompactMaskingKmacError::InvalidCensus);
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    fn add(&self, other: &Self) -> Self {
        Self {
            numerator: &self.numerator * &other.denominator + &other.numerator * &self.denominator,
            denominator: &self.denominator * &other.denominator,
        }
    }

    fn is_at_most_inverse_power_of_two(&self, exponent: usize) -> bool {
        (&self.numerator << exponent) <= self.denominator
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactMaskingKmacQprfHop {
    ActionKeyHierarchy,
    DerivedKeyGraph,
    CompactGenerationExpansion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactMaskingKmacKeyRole {
    ActionRoot,
    PrivateRandomnessStream,
    ProofCoin,
    CompactWhirSeed,
    CompactResponseSaltSeed,
}

/// One symbolic term
/// `key_instance_multiplicity * Adv_KMAC256(query_bound_per_key)`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactMaskingKmacQprfKeyTerm {
    key_role: CompactMaskingKmacKeyRole,
    key_bit_length: u32,
    fixed_customization_domain_count: u32,
    output_bit_lengths: Vec<u32>,
    key_instance_multiplicity: u64,
    honest_query_count_per_key: u64,
    reduction_query_bound_per_key: BigUint,
}

/// One of the three actual KMAC qPRF replacements. The loss remains symbolic
/// because assigning a numeric advantage to fixed KMAC256 would be invented.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactMaskingKmacQprfHopLoss {
    hop: CompactMaskingKmacQprfHop,
    key_terms: Vec<CompactMaskingKmacQprfKeyTerm>,
}

/// Exact known terms plus the three symbolic quantum-PRF replacements for one of
/// the authority-derived application multiplicities.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactMaskingKmacQuantumHybridLoss {
    application_multiplicity: u64,
    /// Each application injects an independent uniform 512-bit root and gets
    /// the declared per-root quantum query budget. The exact term is therefore
    /// `m * (2q + 1)^2 / 2^512`, not `(2mq + 1)^2 / 2^512`.
    action_root_search: ExactProbabilityUpperBound,
    action_root_collision: ExactProbabilityUpperBound,
    /// Collision among fixed 512-bit coordinate-context outputs that share one
    /// derived stream key, in the joint ideal-QRO game. Different applications
    /// have independent roots; their possible key equality is charged by
    /// `action_root_collision` instead of creating cross-key frame pairs.
    coordinate_context_collision: ExactProbabilityUpperBound,
    /// Collision among distinct stream-attempt outputs that share one proof-
    /// coin key after the qPRF replacement. The selected application has one
    /// canonical witness attempt, so this numerator is zero; authenticated
    /// resets repeat it and changed witnesses require a new action root.
    attempt_identifier_collision: ExactProbabilityUpperBound,
    /// Canonical block-tuple collision after the context and attempt outputs
    /// above are fixed and distinct.
    canonical_block_frame_collision: ExactProbabilityUpperBound,
    /// Collision among the coordinate-separated hiding and salt outputs after
    /// the private-randomness PRF is replaced by ideal outputs.
    compact_seed_collision: ExactProbabilityUpperBound,
    /// Rejection sampling is exactly uniform conditioned on non-exhaustion.
    sampler_exhaustion: ExactProbabilityUpperBound,
    leaf_salt_collision: ExactProbabilityUpperBound,
    fiat_shamir_round_salt_collision: ExactProbabilityUpperBound,
    known_loss_sum: ExactProbabilityUpperBound,
    qprf_hops: [CompactMaskingKmacQprfHopLoss; 3],
}

/// Conditional accounting for the selected compact masking hybrid.
///
/// Derivation recomputes the selected contract hash, KMAC census,
/// authority-derived union multiplicity, exact quantum-query terms, and the
/// 256-bit known-loss floor. The three KMAC quantum-PRF advantages remain
/// symbolic. The release bridge names the compatible joint fixed-KMAC256 and
/// fixed-SHAKE256 interface assumption over Keccak-f[1600], but this accounting
/// neither proves that assumption nor grants proof-acceptance authority.
#[cfg(test)]
pub(crate) struct CompactMaskingKmacConditionalHybridAccounting {
    selected_contract_source_hash: Hash512,
    hybrid_loss: CompactMaskingKmacQuantumHybridLoss,
}

/// Production-derived census for one compact public-key-share proof.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactMaskingKmacCensus {
    private_extension_element_count: u64,
    private_base_field_sample_count: u64,
    response_committed_leaf_salt_count: u64,
    minimum_transported_leaf_salt_count: u64,
    maximum_transported_leaf_salt_count: u64,
    response_commitment_count: u32,
    call_rows: [CompactMaskingKmacCallRow; 7],
}

impl CompactMaskingKmacCensus {
    fn quantum_hybrid_loss(
        &self,
        application_multiplicity: u64,
    ) -> Result<CompactMaskingKmacQuantumHybridLoss, CompactMaskingKmacError> {
        if application_multiplicity == 0 {
            return Err(CompactMaskingKmacError::InvalidCensus);
        }

        let action_root_space = BigUint::one() << bit_length(ACTION_RANDOMNESS_ROOT_BYTE_LENGTH)?;
        let query_count = BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET);
        let amplitude_bound = (query_count << 1_usize) + BigUint::one();
        let root_search_numerator =
            &amplitude_bound * &amplitude_bound * BigUint::from(application_multiplicity);
        let action_root_search =
            ExactProbabilityUpperBound::new(root_search_numerator, action_root_space.clone())?;
        let action_root_collision = ExactProbabilityUpperBound::new(
            choose_two(application_multiplicity),
            action_root_space,
        )?;
        let coordinate_context_collision_pair_count = choose_two(
            u64::try_from(COMPACT_GENERATION_PRIVATE_SEED_COORDINATES.len())
                .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?,
        ) * BigUint::from(application_multiplicity);
        let coordinate_context_collision = ExactProbabilityUpperBound::new(
            coordinate_context_collision_pair_count,
            BigUint::one() << SHAKE256_IDEAL_QRO_OUTPUT_BIT_LENGTH,
        )?;
        // One canonical-witness attempt identifier enters the selected proof's
        // block frames. Authenticated resets repeat it; a changed witness needs
        // a fresh action root and counts as another application.
        let attempt_identifier_collision = ExactProbabilityUpperBound::zero();
        let canonical_block_frame_collision = ExactProbabilityUpperBound::zero();
        let total_compact_seed_count = application_multiplicity
            .checked_mul(2)
            .ok_or(CompactMaskingKmacError::ArithmeticOverflow)?;
        let compact_seed_collision = ExactProbabilityUpperBound::new(
            choose_two(total_compact_seed_count),
            BigUint::one() << bit_length(COMPACT_PRIVATE_SEED_BYTE_LENGTH)?,
        )?;

        let sampler_exhaustion = self.sampler_exhaustion(application_multiplicity)?;
        let total_salt_count = self
            .response_committed_leaf_salt_count
            .checked_mul(application_multiplicity)
            .ok_or(CompactMaskingKmacError::ArithmeticOverflow)?;
        let leaf_salt_collision = ExactProbabilityUpperBound::new(
            choose_two(total_salt_count),
            BigUint::one()
                << (COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
                    .checked_mul(8)
                    .ok_or(CompactMaskingKmacError::ArithmeticOverflow)?),
        )?;
        let total_round_salt_count = u64::from(self.response_commitment_count)
            .checked_mul(application_multiplicity)
            .ok_or(CompactMaskingKmacError::ArithmeticOverflow)?;
        let fiat_shamir_round_salt_collision = ExactProbabilityUpperBound::new(
            choose_two(total_round_salt_count),
            BigUint::one()
                << (COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH
                    .checked_mul(8)
                    .ok_or(CompactMaskingKmacError::ArithmeticOverflow)?),
        )?;
        let known_loss_sum = action_root_search
            .add(&action_root_collision)
            .add(&coordinate_context_collision)
            .add(&attempt_identifier_collision)
            .add(&canonical_block_frame_collision)
            .add(&compact_seed_collision)
            .add(&sampler_exhaustion)
            .add(&leaf_salt_collision)
            .add(&fiat_shamir_round_salt_collision);

        let hierarchy_calls = self.call_row(CompactMaskingKmacCallFamily::ActionKeyHierarchy)?;
        let preparation_calls =
            self.call_row(CompactMaskingKmacCallFamily::PersistentProofPreparation)?;
        let witness_calls =
            self.call_row(CompactMaskingKmacCallFamily::PersistentWitnessAttempt)?;
        let private_seed_calls = self.call_row(CompactMaskingKmacCallFamily::PrivateSeedBlocks)?;
        let whir_random_calls =
            self.call_row(CompactMaskingKmacCallFamily::CompactWhirRandomBlocks)?;
        let leaf_salt_calls = self.call_row(CompactMaskingKmacCallFamily::SecretLeafSalts)?;
        let round_salt_calls = self.call_row(CompactMaskingKmacCallFamily::FiatShamirRoundSalts)?;

        let qprf_hops = [
            CompactMaskingKmacQprfHopLoss {
                hop: CompactMaskingKmacQprfHop::ActionKeyHierarchy,
                key_terms: vec![qprf_key_term_from_call_rows(
                    CompactMaskingKmacKeyRole::ActionRoot,
                    application_multiplicity,
                    &[hierarchy_calls],
                )?],
            },
            CompactMaskingKmacQprfHopLoss {
                hop: CompactMaskingKmacQprfHop::DerivedKeyGraph,
                key_terms: vec![
                    qprf_key_term_from_call_rows(
                        CompactMaskingKmacKeyRole::PrivateRandomnessStream,
                        application_multiplicity,
                        &[private_seed_calls],
                    )?,
                    qprf_key_term_from_call_rows(
                        CompactMaskingKmacKeyRole::ProofCoin,
                        application_multiplicity,
                        &[preparation_calls, witness_calls],
                    )?,
                ],
            },
            CompactMaskingKmacQprfHopLoss {
                hop: CompactMaskingKmacQprfHop::CompactGenerationExpansion,
                key_terms: vec![
                    qprf_key_term_from_call_rows(
                        CompactMaskingKmacKeyRole::CompactWhirSeed,
                        application_multiplicity,
                        &[whir_random_calls],
                    )?,
                    qprf_key_term_from_call_rows(
                        CompactMaskingKmacKeyRole::CompactResponseSaltSeed,
                        application_multiplicity,
                        &[leaf_salt_calls, round_salt_calls],
                    )?,
                ],
            },
        ];

        Ok(CompactMaskingKmacQuantumHybridLoss {
            application_multiplicity,
            action_root_search,
            action_root_collision,
            coordinate_context_collision,
            attempt_identifier_collision,
            canonical_block_frame_collision,
            compact_seed_collision,
            sampler_exhaustion,
            leaf_salt_collision,
            fiat_shamir_round_salt_collision,
            known_loss_sum,
            qprf_hops,
        })
    }

    fn sampler_exhaustion(
        &self,
        application_multiplicity: u64,
    ) -> Result<ExactProbabilityUpperBound, CompactMaskingKmacError> {
        let candidate_space = BigUint::one()
            << usize::try_from(PRIVATE_SAMPLER_CANDIDATE_BYTE_LENGTH * 8)
                .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?;
        let rejected_candidate_count = &candidate_space % BigUint::from(PROOF_BASE_FIELD_MODULUS);
        let draw_count = SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT;
        ExactProbabilityUpperBound::new(
            rejected_candidate_count.pow(draw_count)
                * BigUint::from(self.private_base_field_sample_count)
                * BigUint::from(application_multiplicity),
            candidate_space.pow(draw_count),
        )
    }

    fn call_row(
        &self,
        family: CompactMaskingKmacCallFamily,
    ) -> Result<CompactMaskingKmacCallRow, CompactMaskingKmacError> {
        self.call_rows
            .iter()
            .copied()
            .find(|row| row.family == family)
            .ok_or(CompactMaskingKmacError::InvalidCensus)
    }
}

#[cfg(test)]
pub(crate) fn derive_selected_compact_masking_kmac_conditional_hybrid_accounting(
    scope: CompactMaskingKmacUnionScope,
) -> Result<CompactMaskingKmacConditionalHybridAccounting, CompactMaskingKmacError> {
    let (selected_contract_source_hash, hybrid_loss, _census) =
        derive_selected_compact_masking_kmac_components(selected_application_multiplicity(scope)?)?;
    Ok(CompactMaskingKmacConditionalHybridAccounting {
        selected_contract_source_hash,
        hybrid_loss,
    })
}

/// Derives conditional quantum-hybrid accounting for one selected
/// multiplicity. This arithmetic leaves the named joint KMAC256/SHAKE256
/// security assumption unproved and does not mint an authority for it.
fn derive_selected_compact_masking_kmac_components(
    application_multiplicity: u64,
) -> Result<
    (
        Hash512,
        CompactMaskingKmacQuantumHybridLoss,
        CompactMaskingKmacCensus,
    ),
    CompactMaskingKmacError,
> {
    let contract = CompactPublicKeyProofContract::decode_selected()?;
    let selected_contract_source_hash = contract.verifier_inputs().canonical_source_hash()?;
    let census = derive_compact_masking_kmac_census(&contract)?;
    let hybrid_loss = census.quantum_hybrid_loss(application_multiplicity)?;
    enforce_selected_known_loss_floor(&hybrid_loss.known_loss_sum)?;
    Ok((selected_contract_source_hash, hybrid_loss, census))
}

/// Re-derives the live single-proof KMAC bridge from the selected contract and
/// returns its contract hash after deriving the exact call census, known-loss
/// terms, and symbolic quantum-PRF hops. The fixed KMAC256/SHAKE256 joint
/// assumption remains external.
pub(crate) fn derive_selected_compact_masking_kmac_bridge()
-> Result<Hash512, CompactMaskingKmacError> {
    Ok(
        derive_selected_compact_masking_deployment_hybrid_statement()?
            .selected_contract_source_hash,
    )
}

fn derive_selected_compact_masking_deployment_hybrid_statement()
-> Result<CompactMaskingDeploymentHybridStatement, CompactMaskingKmacError> {
    let (selected_contract_source_hash, hybrid_loss, census) =
        derive_selected_compact_masking_kmac_components(1)?;
    let kmac_qprf_hop_count = u8::try_from(hybrid_loss.qprf_hops.len())
        .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?;
    let statement = CompactMaskingDeploymentHybridStatement {
        selected_contract_source_hash,
        browser_action_root_bit_length: bit_length(ACTION_RANDOMNESS_ROOT_BYTE_LENGTH)?,
        quantum_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
        kmac_qprf_hop_count,
        joint_keccak_interface: derive_joint_keccak_interface(&census)?,
        joint_primitive_assumption:
            CompactMaskingJointPrimitiveAssumption::FixedKmac256QprfAndFixedShake256IdealQroWithSharedKeccakF1600,
    };
    statement.validate(selected_contract_source_hash)?;
    Ok(statement)
}

#[cfg(test)]
fn derive_selected_joint_keccak_interface()
-> Result<CompactMaskingJointKeccakInterface, CompactMaskingKmacError> {
    let census = derive_selected_compact_masking_kmac_census_from_source()?;
    derive_joint_keccak_interface(&census)
}

fn derive_joint_keccak_interface(
    census: &CompactMaskingKmacCensus,
) -> Result<CompactMaskingJointKeccakInterface, CompactMaskingKmacError> {
    let mut output_bit_lengths = census
        .call_rows
        .iter()
        .map(|row| row.output_bit_length)
        .collect::<Vec<_>>();
    output_bit_lengths.sort_unstable();
    output_bit_lengths.dedup();
    let output_bit_lengths: [u32; 4] = output_bit_lengths
        .try_into()
        .map_err(|_| CompactMaskingKmacError::InvalidJointKeccakInterface)?;
    if census
        .call_rows
        .iter()
        .any(|row| row.key_bit_length != SELECTED_KMAC_KEY_BIT_LENGTH)
    {
        return Err(CompactMaskingKmacError::InvalidJointKeccakInterface);
    }
    let minimum_kmac_call_count = census.call_rows.iter().try_fold(0_u64, |total, row| {
        checked_add(total, row.minimum_call_count)
    })?;
    let maximum_kmac_call_count = census.call_rows.iter().try_fold(0_u64, |total, row| {
        checked_add(total, row.maximum_call_count)
    })?;
    let interface = CompactMaskingJointKeccakInterface {
        keccak_state_bit_length: KECCAK_F1600_STATE_BIT_LENGTH,
        keccak_permutation_round_count: KECCAK_F1600_PERMUTATION_ROUND_COUNT,
        rate_bit_length: SHAKE256_RATE_BIT_LENGTH,
        capacity_bit_length: SHAKE256_CAPACITY_BIT_LENGTH,
        bytepad_width: SHAKE256_RATE_BYTE_LENGTH,
        shake_delimited_suffix: SHAKE_DELIMITED_SUFFIX,
        shake_fixed_output_bit_length: SHAKE256_IDEAL_QRO_OUTPUT_BIT_LENGTH,
        cshake_delimited_suffix: CSHAKE_DELIMITED_SUFFIX,
        kmac_function_name: KMAC_FUNCTION_NAME,
        kmac_uses_fixed_output_mode: true,
        kmac_key_bit_length: SELECTED_KMAC_KEY_BIT_LENGTH,
        kmac_output_bit_lengths: output_bit_lengths,
        kmac_customization_domains: census.call_rows.map(|row| row.customization),
        minimum_kmac_call_count,
        maximum_kmac_call_count,
    };
    if !interface.has_valid_mode_parameters() {
        return Err(CompactMaskingKmacError::InvalidJointKeccakInterface);
    }
    Ok(interface)
}

#[cfg(test)]
fn derive_selected_compact_masking_kmac_census()
-> Result<CompactMaskingKmacCensus, CompactMaskingKmacError> {
    derive_selected_compact_masking_kmac_census_from_source()
}

#[cfg(test)]
fn derive_selected_compact_masking_kmac_census_from_source()
-> Result<CompactMaskingKmacCensus, CompactMaskingKmacError> {
    let contract = CompactPublicKeyProofContract::decode_selected()?;
    derive_compact_masking_kmac_census(&contract)
}

fn derive_compact_masking_kmac_census(
    contract: &CompactPublicKeyProofContract,
) -> Result<CompactMaskingKmacCensus, CompactMaskingKmacError> {
    let inputs = contract.verifier_inputs();
    if inputs.statement_layout.schema_identifier()
        != ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
    {
        return Err(CompactMaskingKmacError::InvalidCensus);
    }
    let mut private_extension_element_count = 0_u64;
    if inputs.response_merkle_geometries.len() != inputs.proof_wire_geometry.responses().len() {
        return Err(CompactMaskingKmacError::InvalidCensus);
    }
    let mut response_committed_leaf_salt_count = 0_u64;
    let mut minimum_transported_leaf_salt_count = 0_u64;
    let mut maximum_transported_leaf_salt_count = 0_u64;
    for (response_index, geometry) in inputs.response_merkle_geometries.iter().enumerate() {
        if usize::try_from(geometry.response_ordinal()).ok() != Some(response_index) {
            return Err(CompactMaskingKmacError::InvalidCensus);
        }
        response_committed_leaf_salt_count = checked_add(
            response_committed_leaf_salt_count,
            geometry.merkle_leaf_count(),
        )?;
        minimum_transported_leaf_salt_count = checked_add(
            minimum_transported_leaf_salt_count,
            geometry.minimum_queried_leaf_count(),
        )?;
        maximum_transported_leaf_salt_count = checked_add(
            maximum_transported_leaf_salt_count,
            geometry.maximum_queried_leaf_count(),
        )?;
    }
    let response_commitment_count = u32::try_from(inputs.response_merkle_geometries.len())
        .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?;
    for epoch in inputs.whir_epochs {
        let epoch_folds = inputs
            .whir_folds
            .iter()
            .filter(|fold| fold.epoch == epoch.epoch)
            .copied()
            .collect::<Vec<_>>();
        let epoch_randomness = derive_epoch_census(epoch, &epoch_folds, inputs.cfw_configuration)?;
        private_extension_element_count =
            checked_add(private_extension_element_count, epoch_randomness)?;
    }
    let private_base_field_sample_count = checked_product(
        private_extension_element_count,
        u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?,
    )?;
    let minimum_construction_bytes = checked_product(
        private_base_field_sample_count,
        PRIVATE_SAMPLER_CANDIDATE_BYTE_LENGTH,
    )?;
    let maximum_construction_bytes = checked_product(
        minimum_construction_bytes,
        u64::from(SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT),
    )?;
    let private_block_byte_length = u64::try_from(PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH)
        .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?;
    let private_seed_byte_length = u64::try_from(COMPACT_PRIVATE_SEED_BYTE_LENGTH)
        .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?;
    let private_seed_blocks = private_seed_byte_length.div_ceil(private_block_byte_length);
    let private_seed_call_count = checked_product(
        u64::try_from(COMPACT_GENERATION_PRIVATE_SEED_COORDINATES.len())
            .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?,
        private_seed_blocks,
    )?;
    let compact_random_block_byte_length = u64::try_from(COMPACT_WHIR_RANDOM_BLOCK_BYTE_LENGTH)
        .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?;
    let minimum_compact_random_blocks =
        minimum_construction_bytes.div_ceil(compact_random_block_byte_length);
    let maximum_compact_random_blocks =
        maximum_construction_bytes.div_ceil(compact_random_block_byte_length);
    let minimum_leaf_salt_calls = checked_add(
        response_committed_leaf_salt_count,
        minimum_transported_leaf_salt_count,
    )?;
    let maximum_leaf_salt_calls = checked_add(
        response_committed_leaf_salt_count,
        maximum_transported_leaf_salt_count,
    )?;

    let key_bit_length = bit_length(ACTION_RANDOMNESS_ROOT_BYTE_LENGTH)?;
    let stream_key_bit_length = bit_length(PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH)?;
    let proof_coin_key_bit_length = bit_length(PROOF_COIN_KEY_BYTE_LENGTH)?;
    let call_rows = [
        CompactMaskingKmacCallRow {
            family: CompactMaskingKmacCallFamily::ActionKeyHierarchy,
            customization: ACTION_RANDOMNESS_KEY_HIERARCHY_CUSTOMIZATION,
            key_bit_length,
            output_bit_length: bit_length(ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH)?,
            minimum_call_count: 1,
            maximum_call_count: 1,
        },
        CompactMaskingKmacCallRow {
            family: CompactMaskingKmacCallFamily::PersistentProofPreparation,
            customization: PERSISTENT_PROOF_PREPARATION_CUSTOMIZATION,
            key_bit_length: proof_coin_key_bit_length,
            output_bit_length: KMAC256_ATTEMPT_IDENTIFIER_OUTPUT_BIT_LENGTH,
            minimum_call_count: 1,
            maximum_call_count: 1,
        },
        CompactMaskingKmacCallRow {
            family: CompactMaskingKmacCallFamily::PersistentWitnessAttempt,
            customization: PERSISTENT_PROOF_WITNESS_ATTEMPT_CUSTOMIZATION,
            key_bit_length: proof_coin_key_bit_length,
            output_bit_length: KMAC256_ATTEMPT_IDENTIFIER_OUTPUT_BIT_LENGTH,
            minimum_call_count: 1,
            maximum_call_count: 1,
        },
        CompactMaskingKmacCallRow {
            family: CompactMaskingKmacCallFamily::PrivateSeedBlocks,
            customization: PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION,
            key_bit_length: stream_key_bit_length,
            output_bit_length: KMAC256_BLOCK_OUTPUT_BIT_LENGTH,
            minimum_call_count: private_seed_call_count,
            maximum_call_count: private_seed_call_count,
        },
        CompactMaskingKmacCallRow {
            family: CompactMaskingKmacCallFamily::CompactWhirRandomBlocks,
            customization: COMPACT_WHIR_RANDOM_CUSTOMIZATION,
            key_bit_length: bit_length(COMPACT_PRIVATE_SEED_BYTE_LENGTH)?,
            output_bit_length: bit_length(COMPACT_WHIR_RANDOM_BLOCK_BYTE_LENGTH)?,
            minimum_call_count: minimum_compact_random_blocks,
            maximum_call_count: maximum_compact_random_blocks,
        },
        CompactMaskingKmacCallRow {
            family: CompactMaskingKmacCallFamily::SecretLeafSalts,
            customization: COMPACT_PRIVATE_LEAF_SALT_CUSTOMIZATION,
            key_bit_length: bit_length(COMPACT_PRIVATE_SEED_BYTE_LENGTH)?,
            output_bit_length: bit_length(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH)?,
            minimum_call_count: minimum_leaf_salt_calls,
            maximum_call_count: maximum_leaf_salt_calls,
        },
        CompactMaskingKmacCallRow {
            family: CompactMaskingKmacCallFamily::FiatShamirRoundSalts,
            customization: COMPACT_FIAT_SHAMIR_ROUND_SALT_CUSTOMIZATION,
            key_bit_length: bit_length(COMPACT_PRIVATE_SEED_BYTE_LENGTH)?,
            output_bit_length: bit_length(COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH)?,
            minimum_call_count: u64::from(response_commitment_count),
            maximum_call_count: u64::from(response_commitment_count),
        },
    ];
    let census = CompactMaskingKmacCensus {
        private_extension_element_count,
        private_base_field_sample_count,
        response_committed_leaf_salt_count,
        minimum_transported_leaf_salt_count,
        maximum_transported_leaf_salt_count,
        response_commitment_count,
        call_rows,
    };
    Ok(census)
}

fn derive_epoch_census(
    epoch: &CompactWhirEpochContract,
    folds: &[CompactWhirFoldContract],
    cfw_configuration: CompactCfwVerifierConfiguration,
) -> Result<u64, CompactMaskingKmacError> {
    if folds.len() != epoch.folding_schedule.len()
        || folds
            .iter()
            .enumerate()
            .any(|(index, fold)| usize::from(fold.batch_ordinal) != index)
    {
        return Err(CompactMaskingKmacError::InvalidCensus);
    }

    let source_oracle_encoding = folds.iter().try_fold(0_u64, |count, fold| {
        checked_add(count, checked_product(fold.oracle_width, fold.query_count)?)
    })?;
    let all_groups = epoch
        .external_mask_groups
        .iter()
        .chain(&epoch.internal_mask_groups)
        .collect::<Vec<_>>();
    let internal_carried_messages =
        epoch
            .internal_mask_groups
            .iter()
            .try_fold(0_u64, |count, group| match group.role_tag {
                4 => checked_add(count, checked_product(group.width, group.message_length)?),
                5 => Ok(count),
                _ => Err(CompactMaskingKmacError::InvalidCensus),
            })?;
    let cfw_geometry = cfw_configuration.geometry();
    let cfw_inner_mask_count = u64::try_from(cfw_geometry.inner_mask_count())
        .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?;
    let cfw_outer_mask_count = u64::try_from(cfw_geometry.outer_mask_count())
        .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?;
    let cfw_inner_message_length = cfw_configuration.inner_mask_message_length();
    let cfw_inner_endpoint_constraint_count =
        u64::try_from(cfw_configuration.inner_endpoint_targets().len())
            .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?;
    let cfw_inner_independent_element_count = cfw_inner_message_length
        .checked_sub(cfw_inner_endpoint_constraint_count)
        .filter(|count| *count > 0)
        .ok_or(CompactMaskingKmacError::InvalidCensus)?;
    let cfw_outer_message_length = cfw_configuration.outer_mask_message_length();
    let external_carried_messages =
        epoch
            .external_mask_groups
            .iter()
            .try_fold(0_u64, |count, group| {
                match (group.role_tag, group.committed_encoding_source) {
                    (1, 1) => {
                        checked_add(count, checked_product(group.width, group.message_length)?)
                    }
                    (1, 2) => Ok(count),
                    (2, 1)
                        if group.width == cfw_inner_mask_count
                            && group.message_length == cfw_inner_message_length =>
                    {
                        checked_add(
                            count,
                            checked_product(group.width, cfw_inner_independent_element_count)?,
                        )
                    }
                    (3, 1)
                        if group.width == cfw_outer_mask_count
                            && group.message_length == cfw_outer_message_length =>
                    {
                        checked_add(count, checked_product(group.width, group.message_length)?)
                    }
                    _ => Err(CompactMaskingKmacError::InvalidCensus),
                }
            })?;
    let carried_messages = checked_add(internal_carried_messages, external_carried_messages)?;
    let carried_encoding = all_groups
        .iter()
        .copied()
        .filter(|group| group.committed_encoding_source == 1)
        .try_fold(0_u64, |count, group| {
            checked_add(
                count,
                checked_product(group.width, group.randomness_length)?,
            )
        })?;
    let fresh_mirror_messages = all_groups.iter().try_fold(0_u64, |count, group| {
        checked_add(count, checked_product(group.width, group.message_length)?)
    })?;
    let fresh_mirror_encoding = all_groups.iter().try_fold(0_u64, |count, group| {
        checked_add(
            count,
            checked_product(group.width, group.randomness_length)?,
        )
    })?;
    let fresh_source_message = 1_u64
        .checked_shl(epoch.final_variable_count)
        .ok_or(CompactMaskingKmacError::ArithmeticOverflow)?;
    let final_fold = folds.last().ok_or(CompactMaskingKmacError::InvalidCensus)?;
    let private_extension_elements = [
        source_oracle_encoding,
        carried_messages,
        carried_encoding,
        fresh_mirror_messages,
        fresh_mirror_encoding,
        fresh_source_message,
        final_fold.query_count,
    ]
    .into_iter()
    .try_fold(0_u64, checked_add)?;

    Ok(private_extension_elements)
}

#[cfg(test)]
fn selected_application_multiplicity(
    scope: CompactMaskingKmacUnionScope,
) -> Result<u64, CompactMaskingKmacError> {
    match scope {
        CompactMaskingKmacUnionScope::SinglePublicKeyShareProof => Ok(1),
        CompactMaskingKmacUnionScope::SelectedPublicKeyShareRosterUnion => {
            let inventory =
                super::selected_accounting::derive_selected_proof_family_application_inventory()
                    .map_err(|_| CompactMaskingKmacError::InvalidCensus)?;
            let count = inventory
                .family_entry(
                    ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                )
                .ok_or(CompactMaskingKmacError::InvalidCensus)?
                .physical_proof_application_count();
            if count == 0 {
                Err(CompactMaskingKmacError::InvalidCensus)
            } else {
                Ok(u64::from(count))
            }
        }
        CompactMaskingKmacUnionScope::CompletePhysicalProofInventoryMultiplicity => {
            let inventory =
                super::selected_accounting::derive_selected_proof_family_application_inventory()
                    .map_err(|_| CompactMaskingKmacError::InvalidCensus)?;
            let count = inventory
                .total_physical_proof_application_count()
                .map_err(|_| CompactMaskingKmacError::InvalidCensus)?;
            if count == 0 {
                Err(CompactMaskingKmacError::InvalidCensus)
            } else {
                Ok(u64::from(count))
            }
        }
    }
}

fn enforce_selected_known_loss_floor(
    known_loss: &ExactProbabilityUpperBound,
) -> Result<(), CompactMaskingKmacError> {
    if !known_loss.is_at_most_inverse_power_of_two(SELECTED_KNOWN_LOSS_SECURITY_BIT_FLOOR) {
        return Err(CompactMaskingKmacError::KnownLossAboveSelectedFloor);
    }
    Ok(())
}

fn qprf_key_term_from_call_rows(
    key_role: CompactMaskingKmacKeyRole,
    key_instance_multiplicity: u64,
    call_rows: &[CompactMaskingKmacCallRow],
) -> Result<CompactMaskingKmacQprfKeyTerm, CompactMaskingKmacError> {
    let first_row = call_rows
        .first()
        .ok_or(CompactMaskingKmacError::InvalidCensus)?;
    if key_instance_multiplicity == 0 {
        return Err(CompactMaskingKmacError::InvalidCensus);
    }
    let mut honest_query_count_per_key = 0_u64;
    let mut output_bit_lengths = Vec::new();
    for (row_index, row) in call_rows.iter().enumerate() {
        if row.customization.is_empty()
            || row.key_bit_length != first_row.key_bit_length
            || row.output_bit_length == 0
            || row.minimum_call_count == 0
            || row.minimum_call_count > row.maximum_call_count
            || call_rows[..row_index]
                .iter()
                .any(|previous| previous.customization == row.customization)
        {
            return Err(CompactMaskingKmacError::InvalidCensus);
        }
        honest_query_count_per_key =
            checked_add(honest_query_count_per_key, row.maximum_call_count)?;
        if !output_bit_lengths.contains(&row.output_bit_length) {
            output_bit_lengths.push(row.output_bit_length);
        }
    }
    Ok(CompactMaskingKmacQprfKeyTerm {
        key_role,
        key_bit_length: first_row.key_bit_length,
        fixed_customization_domain_count: u32::try_from(call_rows.len())
            .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?,
        output_bit_lengths,
        key_instance_multiplicity,
        honest_query_count_per_key,
        reduction_query_bound_per_key: BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET)
            + BigUint::from(honest_query_count_per_key),
    })
}

fn checked_add(left: u64, right: u64) -> Result<u64, CompactMaskingKmacError> {
    left.checked_add(right)
        .ok_or(CompactMaskingKmacError::ArithmeticOverflow)
}

fn checked_product(left: u64, right: u64) -> Result<u64, CompactMaskingKmacError> {
    left.checked_mul(right)
        .ok_or(CompactMaskingKmacError::ArithmeticOverflow)
}

fn choose_two(value: u64) -> BigUint {
    if value < 2 {
        BigUint::default()
    } else {
        BigUint::from(value) * BigUint::from(value - 1) / BigUint::from(2_u8)
    }
}

fn bit_length(byte_length: usize) -> Result<u32, CompactMaskingKmacError> {
    u32::try_from(
        byte_length
            .checked_mul(8)
            .ok_or(CompactMaskingKmacError::ArithmeticOverflow)?,
    )
    .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use zeroize::Zeroizing;

    use super::*;
    use crate::foundation::{
        ActionPrivateRandomness, ActionRandomnessDerivationInput, ActionRandomnessRoot,
        CanonicalDecodeLimits, CanonicalItemType, CanonicalTuple,
        PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER, PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_VERSION,
        ParticipantIdentity, PersistentProofCoinInput, PrivateRandomBlockInput,
        PrivateRandomnessDomain, ProofApplicationSlot, ProofApplicationSlotCeilings,
    };

    fn hash(fill: u8) -> Hash512 {
        Hash512::from_bytes([fill; Hash512::BYTE_LENGTH])
    }

    fn derivation_input() -> ActionRandomnessDerivationInput {
        ActionRandomnessDerivationInput::new(
            hash(0x11),
            hash(0x22),
            hash(0x33),
            ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH]),
        )
    }

    fn action_randomness() -> ActionPrivateRandomness {
        ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
            [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        ))
        .derive(derivation_input())
        .expect("fixed action randomness derives")
    }

    fn persistent_input() -> PersistentProofCoinInput {
        PersistentProofCoinInput::new(
            ProofApplicationSlot::new(
                hash(0x11),
                hash(0x22),
                hash(0x33),
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(0),
                None,
                None,
            )
            .expect("public-key-share application slot"),
            hash(0x66),
        )
        .expect("persistent compact proof input")
    }

    fn witness_attempt(
        action_randomness: &ActionPrivateRandomness,
        parts: &[&[u8]],
    ) -> crate::foundation::PrivateRandomnessAttemptIdentifier {
        let mut binding = action_randomness
            .begin_persistent_proof_witness_coin_binding(&persistent_input())
            .expect("witness binding starts");
        for part in parts {
            binding
                .absorb_canonical_bytes(part)
                .expect("canonical witness part is framed");
        }
        binding.finish().expect("witness attempt derives")
    }

    #[test]
    fn selected_contract_derives_the_complete_kmac_census() {
        let contract = CompactPublicKeyProofContract::decode_selected()
            .expect("selected compact public-key contract");
        let inputs = contract.verifier_inputs();
        let epoch_randomness = inputs
            .whir_epochs
            .iter()
            .map(|epoch| {
                let folds = inputs
                    .whir_folds
                    .iter()
                    .filter(|fold| fold.epoch == epoch.epoch)
                    .copied()
                    .collect::<Vec<_>>();
                derive_epoch_census(epoch, &folds, inputs.cfw_configuration)
                    .expect("epoch KMAC census derives")
            })
            .collect::<Vec<_>>();
        assert_eq!(epoch_randomness, vec![65_870, 164_618]);

        let census = derive_selected_compact_masking_kmac_census()
            .expect("selected compact masking KMAC census");
        assert_eq!(census.private_extension_element_count, 230_488);
        assert_eq!(census.private_base_field_sample_count, 1_152_440);
        assert_eq!(census.response_committed_leaf_salt_count, 639_270);
        assert!(
            census.minimum_transported_leaf_salt_count < census.maximum_transported_leaf_salt_count
        );
        assert_eq!(census.maximum_transported_leaf_salt_count, 79_310);
        assert!(
            census.maximum_transported_leaf_salt_count < census.response_committed_leaf_salt_count
        );
        assert_eq!(census.response_commitment_count, 82);
        assert_eq!(
            COMPACT_GENERATION_PRIVATE_SEED_COORDINATES,
            [
                CommonProofPrivateCoinCoordinate::hiding_argument(),
                CommonProofPrivateCoinCoordinate::proof_salt(),
            ],
        );
        assert_eq!(
            census.call_rows.map(|row| row.family),
            [
                CompactMaskingKmacCallFamily::ActionKeyHierarchy,
                CompactMaskingKmacCallFamily::PersistentProofPreparation,
                CompactMaskingKmacCallFamily::PersistentWitnessAttempt,
                CompactMaskingKmacCallFamily::PrivateSeedBlocks,
                CompactMaskingKmacCallFamily::CompactWhirRandomBlocks,
                CompactMaskingKmacCallFamily::SecretLeafSalts,
                CompactMaskingKmacCallFamily::FiatShamirRoundSalts,
            ],
        );
        assert_eq!(census.call_rows[0].output_bit_length, 1_536);
        assert_eq!(census.call_rows[1].maximum_call_count, 1);
        assert_eq!(census.call_rows[2].maximum_call_count, 1);
        assert_eq!(census.call_rows[3].maximum_call_count, 2);
        assert_eq!(census.call_rows[4].minimum_call_count, 144_055);
        assert_eq!(census.call_rows[4].maximum_call_count, 9_219_520);
        assert_eq!(
            census.call_rows[5].minimum_call_count,
            census.response_committed_leaf_salt_count + census.minimum_transported_leaf_salt_count,
        );
        assert_eq!(census.call_rows[5].maximum_call_count, 718_580);
        assert_eq!(census.call_rows[6].maximum_call_count, 82);
    }

    #[test]
    fn conditional_hybrid_accounting_binds_selected_contract_and_closed_scopes() {
        let selected_contract_hash = CompactPublicKeyProofContract::decode_selected()
            .expect("selected compact contract decodes")
            .verifier_inputs()
            .canonical_source_hash()
            .expect("selected compact contract hashes");
        let scopes = [
            (
                CompactMaskingKmacUnionScope::SinglePublicKeyShareProof,
                1_u64,
            ),
            (
                CompactMaskingKmacUnionScope::SelectedPublicKeyShareRosterUnion,
                10_u64,
            ),
            (
                CompactMaskingKmacUnionScope::CompletePhysicalProofInventoryMultiplicity,
                103_u64,
            ),
        ];
        for (scope, expected_multiplicity) in scopes {
            let accounting =
                derive_selected_compact_masking_kmac_conditional_hybrid_accounting(scope)
                    .expect("selected conditional hybrid accounting derives");
            assert_eq!(
                accounting.selected_contract_source_hash,
                selected_contract_hash
            );
            assert_eq!(
                accounting.hybrid_loss.application_multiplicity,
                expected_multiplicity,
            );
            assert!(
                accounting
                    .hybrid_loss
                    .known_loss_sum
                    .is_at_most_inverse_power_of_two(SELECTED_KNOWN_LOSS_SECURITY_BIT_FLOOR,),
            );
        }
    }

    #[test]
    fn release_bridge_states_the_browser_root_and_joint_fixed_keccak_assumption() {
        let statement = derive_selected_compact_masking_deployment_hybrid_statement()
            .expect("selected deployment hybrid statement derives");
        let selected_contract_hash = CompactPublicKeyProofContract::decode_selected()
            .expect("selected compact contract decodes")
            .verifier_inputs()
            .canonical_source_hash()
            .expect("selected compact contract hashes");

        assert_eq!(
            statement.validate(selected_contract_hash),
            Ok(selected_contract_hash)
        );
        assert_eq!(statement.browser_action_root_bit_length, 512);
        assert_eq!(
            statement.quantum_query_budget,
            DECLARED_ADVERSARIAL_QUERY_BUDGET
        );
        assert_eq!(statement.kmac_qprf_hop_count, 3);
        assert_eq!(
            statement.joint_keccak_interface.keccak_state_bit_length,
            1_600
        );
        assert_eq!(
            statement
                .joint_keccak_interface
                .keccak_permutation_round_count,
            24
        );
        assert_eq!(statement.joint_keccak_interface.rate_bit_length, 1_088);
        assert_eq!(statement.joint_keccak_interface.capacity_bit_length, 512);
        assert_eq!(statement.joint_keccak_interface.bytepad_width, 136);
        assert_eq!(
            statement
                .joint_keccak_interface
                .shake_fixed_output_bit_length,
            512
        );
        assert_eq!(
            statement.joint_keccak_interface.maximum_kmac_call_count,
            9_938_187
        );
        assert_eq!(
            statement.joint_primitive_assumption.identifier(),
            "fixed-kmac256-qprf-and-fixed-shake256-ideal-qro-with-shared-keccak-f1600"
        );
        assert_eq!(
            derive_selected_compact_masking_kmac_bridge(),
            Ok(selected_contract_hash)
        );

        for invalid_statement in [
            CompactMaskingDeploymentHybridStatement {
                selected_contract_source_hash: hash(0xee),
                ..statement
            },
            CompactMaskingDeploymentHybridStatement {
                browser_action_root_bit_length: 256,
                ..statement
            },
            CompactMaskingDeploymentHybridStatement {
                quantum_query_budget: statement.quantum_query_budget - 1,
                ..statement
            },
            CompactMaskingDeploymentHybridStatement {
                kmac_qprf_hop_count: 2,
                ..statement
            },
            CompactMaskingDeploymentHybridStatement {
                joint_keccak_interface: CompactMaskingJointKeccakInterface {
                    shake_delimited_suffix: 0x04,
                    ..statement.joint_keccak_interface
                },
                ..statement
            },
        ] {
            assert_eq!(
                invalid_statement.validate(selected_contract_hash),
                Err(CompactMaskingKmacError::InvalidJointKeccakInterface)
            );
        }
    }

    #[test]
    fn quantum_hybrid_charges_all_three_symbolic_qprf_hops() {
        let census = derive_selected_compact_masking_kmac_census()
            .expect("selected compact masking KMAC census");
        let accounting = derive_selected_compact_masking_kmac_conditional_hybrid_accounting(
            CompactMaskingKmacUnionScope::SelectedPublicKeyShareRosterUnion,
        )
        .expect("conditional quantum ten-proof union accounting");
        let quantum = accounting.hybrid_loss;

        let amplitude =
            (BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET) << 1_usize) + BigUint::one();
        assert_eq!(
            quantum.action_root_search.numerator,
            &amplitude * &amplitude * BigUint::from(10_u8),
        );
        assert_eq!(
            quantum.action_root_collision.numerator,
            BigUint::from(45_u8),
        );
        assert_eq!(
            quantum.coordinate_context_collision.numerator,
            BigUint::from(10_u8),
        );
        assert_eq!(
            quantum.attempt_identifier_collision.numerator,
            BigUint::default(),
        );
        assert_eq!(
            quantum.canonical_block_frame_collision,
            ExactProbabilityUpperBound::zero(),
        );
        assert_eq!(quantum.compact_seed_collision.numerator, choose_two(20),);
        assert_eq!(
            quantum.leaf_salt_collision.numerator,
            choose_two(10 * census.response_committed_leaf_salt_count),
        );
        assert_eq!(
            quantum.fiat_shamir_round_salt_collision.numerator,
            choose_two(10 * u64::from(census.response_commitment_count)),
        );
        assert_eq!(
            quantum
                .qprf_hops
                .iter()
                .map(|hop| hop.hop)
                .collect::<Vec<_>>(),
            vec![
                CompactMaskingKmacQprfHop::ActionKeyHierarchy,
                CompactMaskingKmacQprfHop::DerivedKeyGraph,
                CompactMaskingKmacQprfHop::CompactGenerationExpansion,
            ],
        );
        assert_eq!(quantum.qprf_hops[0].key_terms.len(), 1);
        assert_eq!(quantum.qprf_hops[1].key_terms.len(), 2);
        assert_eq!(quantum.qprf_hops[2].key_terms.len(), 2);
        let hierarchy = &quantum.qprf_hops[0].key_terms[0];
        assert_eq!(hierarchy.key_role, CompactMaskingKmacKeyRole::ActionRoot);
        assert_eq!(hierarchy.key_bit_length, 512);
        assert_eq!(hierarchy.fixed_customization_domain_count, 1);
        assert_eq!(hierarchy.output_bit_lengths, vec![1_536]);
        assert_eq!(hierarchy.key_instance_multiplicity, 10);
        assert_eq!(hierarchy.honest_query_count_per_key, 1);
        assert_eq!(
            hierarchy.reduction_query_bound_per_key,
            BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET) + BigUint::one(),
        );
        assert_eq!(
            quantum.qprf_hops[1]
                .key_terms
                .iter()
                .map(|term| (term.key_role, term.key_instance_multiplicity))
                .collect::<Vec<_>>(),
            vec![
                (CompactMaskingKmacKeyRole::PrivateRandomnessStream, 10),
                (CompactMaskingKmacKeyRole::ProofCoin, 10),
            ],
        );
        let stream = &quantum.qprf_hops[1].key_terms[0];
        assert_eq!(stream.key_bit_length, 512);
        assert_eq!(stream.fixed_customization_domain_count, 1);
        assert_eq!(stream.output_bit_lengths, vec![512]);
        assert_eq!(stream.honest_query_count_per_key, 2);
        assert_eq!(
            stream.reduction_query_bound_per_key,
            BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET) + BigUint::from(2_u8),
        );
        let proof_coin = &quantum.qprf_hops[1].key_terms[1];
        assert_eq!(proof_coin.key_bit_length, 512);
        assert_eq!(proof_coin.fixed_customization_domain_count, 2);
        assert_eq!(proof_coin.output_bit_lengths, vec![256]);
        assert_eq!(proof_coin.honest_query_count_per_key, 2,);
        assert_eq!(
            proof_coin.reduction_query_bound_per_key,
            BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET) + BigUint::from(2_u8),
        );
        let compact_whir = &quantum.qprf_hops[2].key_terms[0];
        assert_eq!(
            compact_whir.key_role,
            CompactMaskingKmacKeyRole::CompactWhirSeed,
        );
        assert_eq!(compact_whir.fixed_customization_domain_count, 1);
        assert_eq!(compact_whir.output_bit_lengths, vec![512]);
        assert_eq!(compact_whir.honest_query_count_per_key, 9_219_520);
        let response_salts = &quantum.qprf_hops[2].key_terms[1];
        assert_eq!(
            response_salts.key_role,
            CompactMaskingKmacKeyRole::CompactResponseSaltSeed,
        );
        assert_eq!(response_salts.fixed_customization_domain_count, 2);
        assert_eq!(response_salts.output_bit_lengths, vec![1_024, 512]);
        assert_eq!(response_salts.honest_query_count_per_key, 718_662);
        assert!(
            quantum
                .sampler_exhaustion
                .is_at_most_inverse_power_of_two(1_900)
        );
    }

    #[test]
    fn known_loss_floor_refuses_a_bound_above_256_bits() {
        let insufficient = ExactProbabilityUpperBound::new(
            BigUint::one(),
            BigUint::one() << (SELECTED_KNOWN_LOSS_SECURITY_BIT_FLOOR - 1),
        )
        .expect("positive denominator");
        assert_eq!(
            enforce_selected_known_loss_floor(&insufficient),
            Err(CompactMaskingKmacError::KnownLossAboveSelectedFloor),
        );
    }

    #[test]
    fn canonical_block_frames_reject_every_coordinate_collision_attempt() {
        let action_randomness = action_randomness();
        let attempt = witness_attempt(&action_randomness, &[b"witness-domain", b"witness"]);
        let derivation = derivation_input();
        let family = ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
        let hiding_coordinate = CommonProofPrivateCoinCoordinate::hiding_argument();
        let salt_coordinate = CommonProofPrivateCoinCoordinate::proof_salt();
        let binding = hash(0x77);
        let hiding_context = common_proof_private_coin_coordinate_derivation_context_hash(
            binding,
            hiding_coordinate,
        );
        let salt_context =
            common_proof_private_coin_coordinate_derivation_context_hash(binding, salt_coordinate);
        let hiding_domain =
            PrivateRandomnessDomain::reset_safe_proof(family, hiding_coordinate.purpose_class())
                .expect("hiding coordinate is assigned");
        let salt_domain =
            PrivateRandomnessDomain::reset_safe_proof(family, salt_coordinate.purpose_class())
                .expect("salt coordinate is assigned");

        let encode = |derivation, domain, context, attempt, counter| {
            PrivateRandomBlockInput::new(derivation, domain, context, attempt, counter)
                .expect("block frame is well formed")
                .encode()
                .expect("block frame encodes")
        };
        let baseline = encode(derivation, hiding_domain, hiding_context, attempt, 0);
        let tuple = CanonicalTuple::decode(&baseline, &CanonicalDecodeLimits::default())
            .expect("block tuple decodes");
        assert_eq!(
            tuple.schema_identifier,
            PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER
        );
        assert_eq!(
            tuple.schema_version,
            PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_VERSION
        );
        assert_eq!(
            tuple
                .items
                .iter()
                .map(|item| item.item_type())
                .collect::<Vec<_>>(),
            vec![
                CanonicalItemType::Unsigned16,
                CanonicalItemType::Hash512,
                CanonicalItemType::Hash512,
                CanonicalItemType::Hash512,
                CanonicalItemType::ParticipantIdentity,
                CanonicalItemType::Unsigned16,
                CanonicalItemType::Unsigned16,
                CanonicalItemType::Hash512,
                CanonicalItemType::RawBytes,
                CanonicalItemType::Unsigned64,
            ],
        );
        let changed_attempt =
            witness_attempt(&action_randomness, &[b"witness-domain", b"changed-witness"]);
        let changed_family = PrivateRandomnessDomain::reset_safe_proof(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            hiding_coordinate.purpose_class(),
        )
        .expect("second proof family is assigned");
        let changed_derivations = [
            ActionRandomnessDerivationInput::new(
                hash(0x12),
                hash(0x22),
                hash(0x33),
                ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH]),
            ),
            ActionRandomnessDerivationInput::new(
                hash(0x11),
                hash(0x23),
                hash(0x33),
                ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH]),
            ),
            ActionRandomnessDerivationInput::new(
                hash(0x11),
                hash(0x22),
                hash(0x34),
                ParticipantIdentity::from_bytes([0x44; ParticipantIdentity::BYTE_LENGTH]),
            ),
            ActionRandomnessDerivationInput::new(
                hash(0x11),
                hash(0x22),
                hash(0x33),
                ParticipantIdentity::from_bytes([0x45; ParticipantIdentity::BYTE_LENGTH]),
            ),
        ];
        let mut hostile_frames = vec![
            encode(derivation, changed_family, hiding_context, attempt, 0),
            encode(derivation, salt_domain, hiding_context, attempt, 0),
            encode(derivation, salt_domain, salt_context, attempt, 0),
            encode(derivation, hiding_domain, hash(0x78), attempt, 0),
            encode(
                derivation,
                hiding_domain,
                hiding_context,
                changed_attempt,
                0,
            ),
            encode(derivation, hiding_domain, hiding_context, attempt, 1),
        ];
        hostile_frames.extend(
            changed_derivations
                .into_iter()
                .map(|changed| encode(changed, hiding_domain, hiding_context, attempt, 0)),
        );
        let mut distinct = BTreeSet::from([baseline.clone()]);
        for hostile in hostile_frames {
            assert_ne!(hostile, baseline);
            assert!(distinct.insert(hostile));
        }
        for frame in distinct {
            let decoded =
                PrivateRandomBlockInput::decode(&frame, &CanonicalDecodeLimits::default())
                    .expect("canonical hostile frame decodes uniquely");
            assert_eq!(decoded.encode().expect("decoded frame reencodes"), frame);
        }

        for range in [0..2, 2..4, 14..16] {
            let mut noncanonical_header = baseline.clone();
            noncanonical_header[range].fill(0xff);
            assert!(
                PrivateRandomBlockInput::decode(
                    &noncanonical_header,
                    &CanonicalDecodeLimits::default(),
                )
                .is_err(),
                "schema identifier, schema version, and protocol version are load-bearing",
            );
        }
    }

    #[test]
    fn operative_kmac_distinguishes_length_boundaries_and_stream_coordinates() {
        let action_randomness = action_randomness();
        let left = witness_attempt(&action_randomness, &[b"ab", b"c"]);
        let right = witness_attempt(&action_randomness, &[b"a", b"bc"]);
        let with_empty = witness_attempt(&action_randomness, &[b"ab", b"", b"c"]);
        assert_ne!(left.as_bytes(), right.as_bytes());
        assert_ne!(left.as_bytes(), with_empty.as_bytes());
        assert_ne!(right.as_bytes(), with_empty.as_bytes());

        let family = ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
        let binding = hash(0x77);
        let mut first_blocks = BTreeSet::new();
        for coordinate in [
            CommonProofPrivateCoinCoordinate::hiding_argument(),
            CommonProofPrivateCoinCoordinate::proof_salt(),
        ] {
            let domain =
                PrivateRandomnessDomain::reset_safe_proof(family, coordinate.purpose_class())
                    .expect("selected coordinate is assigned");
            let context =
                common_proof_private_coin_coordinate_derivation_context_hash(binding, coordinate);
            let mut stream = action_randomness
                .begin_stream(domain, context, left)
                .expect("private stream starts");
            let mut block = [0_u8; PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH];
            stream
                .fill_bytes(&mut block)
                .expect("first KMAC block derives");
            assert!(first_blocks.insert(block));
        }
        assert_eq!(first_blocks.len(), 2);
    }
}

#[cfg(test)]
#[path = "compact_masking_kmac/joint_keccak_evidence.rs"]
mod joint_keccak_evidence;
#[cfg(test)]
pub(crate) use joint_keccak_evidence::derive_source_verified_compact_joint_keccak_evidence;
