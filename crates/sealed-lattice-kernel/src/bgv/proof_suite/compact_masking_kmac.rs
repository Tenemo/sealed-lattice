//! KMAC coordinates and conditional generator-hybrid accounting for compact masking.
//!
//! The frozen compact-proof contract is the only geometry input. This module
//! derives every construction-hiding field sample and secret Merkle-leaf salt
//! from that contract, maps them to the two production private-coin streams,
//! and accounts for the exact KMAC call domains. The resulting conditional
//! accounting keeps computational KMAC advantages symbolic while calculating
//! every statistical or information-theoretic term as an exact rational number.

use num_bigint::BigUint;
use num_traits::One;

use super::compact_cfw_geometry::CompactCfwVerifierConfiguration;
use super::compact_proof_contract::{
    CompactProofContractError, CompactPublicKeyProofContract, CompactWhirEpochContract,
    CompactWhirFoldContract,
};
use super::prover::{
    COMMON_PROOF_PRIVATE_COIN_COORDINATE_HASH_DOMAIN, CommonProofPrivateCoinCoordinate,
    common_proof_private_coin_coordinate_derivation_context_hash,
};
use super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE,
};
use crate::foundation::{
    ACTION_RANDOMNESS_KEY_HIERARCHY_CUSTOMIZATION, ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH,
    ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, DECLARED_ADVERSARIAL_QUERY_BUDGET, Hash512,
    ORDINARY_PROOF_ATTEMPT_CUSTOMIZATION, PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER,
    PERSISTENT_PROOF_PREPARATION_CUSTOMIZATION, PERSISTENT_PROOF_WITNESS_ATTEMPT_CUSTOMIZATION,
    PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER, PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_VERSION,
    PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH, PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION,
    PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH, PROOF_COIN_KEY_BYTE_LENGTH,
    ProofApplicationSlotCeilings, SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
    SETUP_ATTEMPT_CUSTOMIZATION, TARGET_RELEASE_ATTEMPT_CUSTOMIZATION,
};

const PRIVATE_SAMPLER_CANDIDATE_BYTE_LENGTH: u64 = size_of::<u64>() as u64;
const KMAC256_ATTEMPT_IDENTIFIER_OUTPUT_BIT_LENGTH: u32 = 256;
const KMAC256_BLOCK_OUTPUT_BIT_LENGTH: u32 = 512;
const SHAKE256_IDEAL_QRO_OUTPUT_BIT_LENGTH: u32 = 512;
/// The exact known terms must stay below the nominal 256-bit computational
/// primitive ceiling. Symbolic KMAC quantum-PRF advantages are deliberately
/// excluded from this numeric gate.
const SELECTED_KNOWN_LOSS_SECURITY_BIT_FLOOR: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactMaskingKmacError {
    Contract(CompactProofContractError),
    ArithmeticOverflow,
    InvalidCensus,
    KnownLossAboveSelectedFloor,
}

impl From<CompactProofContractError> for CompactMaskingKmacError {
    fn from(error: CompactProofContractError) -> Self {
        Self::Contract(error)
    }
}

/// The only union multiplicities for which the selected compact-proof
/// arithmetic is retained. The multi-proof cases are union bounds only; they
/// do not establish shared-oracle, resettable, or family simulation.
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
enum CompactMaskingPrivateCoinOperation {
    ModuloSamples {
        modulus: u64,
        output_count: u64,
        maximum_candidate_draws_per_output: u32,
    },
    RawBytes {
        byte_count: u64,
    },
}

/// One complete private-coin stream coordinate and its canonical block range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactMaskingKmacCoordinateRow {
    coordinate: CommonProofPrivateCoinCoordinate,
    operation: CompactMaskingPrivateCoinOperation,
    /// Distinct canonical block frames on every non-aborting execution.
    minimum_distinct_block_frame_count: u64,
    /// Distinct canonical block frames if every modular output consumes its
    /// complete rejection-sampling allowance.
    maximum_distinct_block_frame_count: u64,
}

impl CompactMaskingKmacCoordinateRow {
    const fn purpose_class(self) -> u16 {
        self.coordinate.purpose_class()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactMaskingKmacCallFamily {
    ActionKeyHierarchy,
    SetupAttempt,
    PersistentProofPreparation,
    PersistentWitnessAttempt,
    OrdinaryProofAttempt,
    TargetReleaseAttempt,
    ConstructionMaskBlocks,
    SecretLeafSaltBlocks,
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

/// The ten typed fields in the operative canonical block-input tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactMaskingBlockFrameField {
    ProtocolVersionU16,
    SuiteIdentifierHash512,
    CeremonyContextHash512,
    ActionContextHash512,
    ParticipantIdentity,
    ProofFamilyU16,
    PurposeClassU16,
    CoordinateContextHash512,
    AttemptIdentifierBytes32,
    BlockCounterU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactMaskingProofAttemptAuthority {
    PersistentResetSafeCanonicalWitness,
}

/// Full framing chain from the selected proof application to a KMAC block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactMaskingKmacFraming {
    proof_family_schema_identifier: u16,
    attempt_authority: CompactMaskingProofAttemptAuthority,
    persistent_input_schema_identifier: u16,
    preparation_customization: &'static [u8],
    witness_attempt_customization: &'static [u8],
    witness_part_length_prefix_byte_length: u8,
    coordinate_context_hash_domain: &'static str,
    coordinate_context_parts: [CompactMaskingCoordinateContextPart; 3],
    /// Hiding and salt are the two fixed context inputs per application.
    distinct_coordinate_context_input_count_per_application: u32,
    /// One canonical-witness attempt identifier enters block frames.
    /// Authenticated resets repeat that input; a changed witness requires a
    /// fresh action root and is counted as another application.
    distinct_stream_attempt_input_count_per_application: u32,
    block_customization: &'static [u8],
    block_input_schema_identifier: u16,
    block_input_schema_version: u16,
    block_input_fields: [CompactMaskingBlockFrameField; 10],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactMaskingCoordinateContextPart {
    DerivationBindingHash512,
    PurposeClassU16LittleEndian,
    OrdinalU32LittleEndian,
}

impl CompactMaskingKmacFraming {
    fn selected() -> Self {
        Self {
            proof_family_schema_identifier:
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            attempt_authority:
                CompactMaskingProofAttemptAuthority::PersistentResetSafeCanonicalWitness,
            persistent_input_schema_identifier: PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER,
            preparation_customization: PERSISTENT_PROOF_PREPARATION_CUSTOMIZATION,
            witness_attempt_customization: PERSISTENT_PROOF_WITNESS_ATTEMPT_CUSTOMIZATION,
            witness_part_length_prefix_byte_length: 8,
            coordinate_context_hash_domain: COMMON_PROOF_PRIVATE_COIN_COORDINATE_HASH_DOMAIN,
            coordinate_context_parts: [
                CompactMaskingCoordinateContextPart::DerivationBindingHash512,
                CompactMaskingCoordinateContextPart::PurposeClassU16LittleEndian,
                CompactMaskingCoordinateContextPart::OrdinalU32LittleEndian,
            ],
            distinct_coordinate_context_input_count_per_application: 2,
            distinct_stream_attempt_input_count_per_application: 1,
            block_customization: PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION,
            block_input_schema_identifier: PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER,
            block_input_schema_version: PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_VERSION,
            block_input_fields: [
                CompactMaskingBlockFrameField::ProtocolVersionU16,
                CompactMaskingBlockFrameField::SuiteIdentifierHash512,
                CompactMaskingBlockFrameField::CeremonyContextHash512,
                CompactMaskingBlockFrameField::ActionContextHash512,
                CompactMaskingBlockFrameField::ParticipantIdentity,
                CompactMaskingBlockFrameField::ProofFamilyU16,
                CompactMaskingBlockFrameField::PurposeClassU16,
                CompactMaskingBlockFrameField::CoordinateContextHash512,
                CompactMaskingBlockFrameField::AttemptIdentifierBytes32,
                CompactMaskingBlockFrameField::BlockCounterU64,
            ],
        }
    }

    fn validate(self) -> Result<(), CompactMaskingKmacError> {
        if self != Self::selected()
            || !ProofApplicationSlotCeilings::SECRET_BEARING_FAMILY_SCHEMA_IDENTIFIERS
                .contains(&self.proof_family_schema_identifier)
        {
            return Err(CompactMaskingKmacError::InvalidCensus);
        }
        Ok(())
    }
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactMaskingKmacKeyRole {
    ActionRoot,
    PrivateRandomnessStream,
    ProofCoin,
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

/// One of the two actual KMAC qPRF replacements. The loss remains symbolic
/// because assigning a numeric advantage to fixed KMAC256 would be invented.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactMaskingKmacQprfHopLoss {
    hop: CompactMaskingKmacQprfHop,
    key_terms: Vec<CompactMaskingKmacQprfKeyTerm>,
}

/// Exact known terms plus the two symbolic quantum-PRF replacements for one of
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
    /// Rejection sampling is exactly uniform conditioned on non-exhaustion.
    sampler_exhaustion: ExactProbabilityUpperBound,
    leaf_salt_collision: ExactProbabilityUpperBound,
    known_loss_sum: ExactProbabilityUpperBound,
    qprf_hops: [CompactMaskingKmacQprfHopLoss; 2],
}

/// Conditional accounting for the selected compact masking hybrid.
///
/// Derivation recomputes the selected contract hash, KMAC census,
/// authority-derived union multiplicity, exact quantum-query terms, and the
/// 256-bit known-loss floor. The two KMAC quantum-PRF advantages remain
/// symbolic. Joint security of the fixed KMAC256 and SHAKE256 interfaces over
/// Keccak-f is an external unproved assumption; this accounting neither
/// instantiates that assumption nor grants proof-acceptance authority.
pub(crate) struct CompactMaskingKmacConditionalHybridAccounting {
    selected_contract_source_hash: Hash512,
    scope: CompactMaskingKmacUnionScope,
    hybrid_loss: CompactMaskingKmacQuantumHybridLoss,
}

/// Production-derived census for one compact public-key-share proof.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactMaskingKmacCertificate {
    private_extension_element_count: u64,
    private_base_field_sample_count: u64,
    response_committed_leaf_salt_count: u64,
    minimum_transported_leaf_salt_count: u64,
    maximum_transported_leaf_salt_count: u64,
    response_commitment_count: u32,
    committed_leaf_salt_count: u64,
    coordinate_rows: [CompactMaskingKmacCoordinateRow; 2],
    call_rows: [CompactMaskingKmacCallRow; 8],
    framing: CompactMaskingKmacFraming,
}

impl CompactMaskingKmacCertificate {
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
        let coordinate_context_collision_pair_count = choose_two(u64::from(
            self.framing
                .distinct_coordinate_context_input_count_per_application,
        )) * BigUint::from(application_multiplicity);
        let coordinate_context_collision = ExactProbabilityUpperBound::new(
            coordinate_context_collision_pair_count,
            BigUint::one() << SHAKE256_IDEAL_QRO_OUTPUT_BIT_LENGTH,
        )?;
        let attempt_identifier_collision_pair_count = choose_two(u64::from(
            self.framing
                .distinct_stream_attempt_input_count_per_application,
        )) * BigUint::from(application_multiplicity);
        let attempt_identifier_collision = ExactProbabilityUpperBound::new(
            attempt_identifier_collision_pair_count,
            BigUint::one() << KMAC256_ATTEMPT_IDENTIFIER_OUTPUT_BIT_LENGTH,
        )?;
        let canonical_block_frame_collision = ExactProbabilityUpperBound::zero();

        let sampler_exhaustion = self.sampler_exhaustion(application_multiplicity)?;
        let total_salt_count = self
            .committed_leaf_salt_count
            .checked_mul(application_multiplicity)
            .ok_or(CompactMaskingKmacError::ArithmeticOverflow)?;
        let leaf_salt_collision = ExactProbabilityUpperBound::new(
            choose_two(total_salt_count),
            BigUint::one()
                << (COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
                    .checked_mul(8)
                    .ok_or(CompactMaskingKmacError::ArithmeticOverflow)?),
        )?;
        let known_loss_sum = action_root_search
            .add(&action_root_collision)
            .add(&coordinate_context_collision)
            .add(&attempt_identifier_collision)
            .add(&canonical_block_frame_collision)
            .add(&sampler_exhaustion)
            .add(&leaf_salt_collision);

        let hierarchy_calls = self.call_row(CompactMaskingKmacCallFamily::ActionKeyHierarchy)?;
        let preparation_calls =
            self.call_row(CompactMaskingKmacCallFamily::PersistentProofPreparation)?;
        let witness_calls =
            self.call_row(CompactMaskingKmacCallFamily::PersistentWitnessAttempt)?;
        let construction_calls =
            self.call_row(CompactMaskingKmacCallFamily::ConstructionMaskBlocks)?;
        let salt_calls = self.call_row(CompactMaskingKmacCallFamily::SecretLeafSaltBlocks)?;
        let maximum_stream_calls = construction_calls
            .maximum_call_count
            .checked_add(salt_calls.maximum_call_count)
            .ok_or(CompactMaskingKmacError::ArithmeticOverflow)?;
        let proof_coin_calls = preparation_calls
            .maximum_call_count
            .checked_add(witness_calls.maximum_call_count)
            .ok_or(CompactMaskingKmacError::ArithmeticOverflow)?;

        let qprf_hops = [
            CompactMaskingKmacQprfHopLoss {
                hop: CompactMaskingKmacQprfHop::ActionKeyHierarchy,
                key_terms: vec![qprf_key_term(
                    CompactMaskingKmacKeyRole::ActionRoot,
                    hierarchy_calls.key_bit_length,
                    1,
                    vec![hierarchy_calls.output_bit_length],
                    application_multiplicity,
                    hierarchy_calls.maximum_call_count,
                )],
            },
            CompactMaskingKmacQprfHopLoss {
                hop: CompactMaskingKmacQprfHop::DerivedKeyGraph,
                key_terms: vec![
                    qprf_key_term(
                        CompactMaskingKmacKeyRole::PrivateRandomnessStream,
                        construction_calls.key_bit_length,
                        1,
                        vec![construction_calls.output_bit_length],
                        application_multiplicity,
                        maximum_stream_calls,
                    ),
                    qprf_key_term(
                        CompactMaskingKmacKeyRole::ProofCoin,
                        preparation_calls.key_bit_length,
                        2,
                        vec![preparation_calls.output_bit_length],
                        application_multiplicity,
                        proof_coin_calls,
                    ),
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
            sampler_exhaustion,
            leaf_salt_collision,
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

    fn validate(&self) -> Result<(), CompactMaskingKmacError> {
        self.framing.validate()?;
        if self.private_extension_element_count == 0
            || self.private_base_field_sample_count
                != self
                    .private_extension_element_count
                    .checked_mul(
                        u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
                            .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?,
                    )
                    .ok_or(CompactMaskingKmacError::ArithmeticOverflow)?
            || self.committed_leaf_salt_count == 0
            || self.committed_leaf_salt_count != self.response_committed_leaf_salt_count
            || self.minimum_transported_leaf_salt_count == 0
            || self.minimum_transported_leaf_salt_count > self.maximum_transported_leaf_salt_count
            || self.maximum_transported_leaf_salt_count > self.committed_leaf_salt_count
            || self.response_commitment_count == 0
            || self.coordinate_rows[0].coordinate
                != CommonProofPrivateCoinCoordinate::hiding_argument()
            || self.coordinate_rows[1].coordinate != CommonProofPrivateCoinCoordinate::proof_salt()
            || self.coordinate_rows[0].coordinate.purpose_class()
                == self.coordinate_rows[1].coordinate.purpose_class()
            || self.coordinate_rows.iter().any(|row| {
                row.minimum_distinct_block_frame_count == 0
                    || row.minimum_distinct_block_frame_count
                        > row.maximum_distinct_block_frame_count
            })
        {
            return Err(CompactMaskingKmacError::InvalidCensus);
        }

        for row in self.coordinate_rows {
            let domain = crate::foundation::PrivateRandomnessDomain::reset_safe_proof(
                self.framing.proof_family_schema_identifier,
                row.purpose_class(),
            )
            .map_err(|_| CompactMaskingKmacError::InvalidCensus)?;
            if domain.family() != self.framing.proof_family_schema_identifier
                || domain.purpose() != row.purpose_class()
            {
                return Err(CompactMaskingKmacError::InvalidCensus);
            }
        }

        let expected_call_families = [
            CompactMaskingKmacCallFamily::ActionKeyHierarchy,
            CompactMaskingKmacCallFamily::SetupAttempt,
            CompactMaskingKmacCallFamily::PersistentProofPreparation,
            CompactMaskingKmacCallFamily::PersistentWitnessAttempt,
            CompactMaskingKmacCallFamily::OrdinaryProofAttempt,
            CompactMaskingKmacCallFamily::TargetReleaseAttempt,
            CompactMaskingKmacCallFamily::ConstructionMaskBlocks,
            CompactMaskingKmacCallFamily::SecretLeafSaltBlocks,
        ];
        if self.call_rows.map(|row| row.family) != expected_call_families
            || self.call_rows.iter().any(|row| {
                row.customization.is_empty()
                    || row.key_bit_length != 512
                    || row.output_bit_length == 0
                    || row.minimum_call_count > row.maximum_call_count
            })
            || self.call_rows[0].customization != ACTION_RANDOMNESS_KEY_HIERARCHY_CUSTOMIZATION
            || self.call_rows[1].customization != SETUP_ATTEMPT_CUSTOMIZATION
            || self.call_rows[2].customization != PERSISTENT_PROOF_PREPARATION_CUSTOMIZATION
            || self.call_rows[3].customization != PERSISTENT_PROOF_WITNESS_ATTEMPT_CUSTOMIZATION
            || self.call_rows[4].customization != ORDINARY_PROOF_ATTEMPT_CUSTOMIZATION
            || self.call_rows[5].customization != TARGET_RELEASE_ATTEMPT_CUSTOMIZATION
            || self.call_rows[6].customization != PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION
            || self.call_rows[7].customization != PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION
            || self.call_rows[0].minimum_call_count != 1
            || self.call_rows[1].maximum_call_count != 0
            || self.call_rows[2].minimum_call_count != 1
            || self.call_rows[3].minimum_call_count != 1
            || self.call_rows[4].maximum_call_count != 0
            || self.call_rows[5].maximum_call_count != 0
            || self.call_rows[6].minimum_call_count == 0
            || self.call_rows[7].minimum_call_count == 0
        {
            return Err(CompactMaskingKmacError::InvalidCensus);
        }

        // The coordinate-domain hash is not used as an injectivity claim. The
        // selected streams also carry their distinct purpose classes directly
        // in the canonical block tuple; this check merely ensures the operative
        // context derivation consumes the two different coordinates.
        let zero_binding = Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH]);
        if common_proof_private_coin_coordinate_derivation_context_hash(
            zero_binding,
            self.coordinate_rows[0].coordinate,
        ) == common_proof_private_coin_coordinate_derivation_context_hash(
            zero_binding,
            self.coordinate_rows[1].coordinate,
        ) {
            return Err(CompactMaskingKmacError::InvalidCensus);
        }
        Ok(())
    }
}

/// Derives conditional quantum-hybrid accounting for one closed selected
/// multiplicity. This arithmetic leaves the external joint KMAC256/SHAKE256
/// security assumption unproved and does not mint an authority for it.
pub(crate) fn derive_selected_compact_masking_kmac_conditional_hybrid_accounting(
    scope: CompactMaskingKmacUnionScope,
) -> Result<CompactMaskingKmacConditionalHybridAccounting, CompactMaskingKmacError> {
    let contract = CompactPublicKeyProofContract::decode_selected()?;
    let selected_contract_source_hash = contract.verifier_inputs().canonical_source_hash()?;
    let certificate = derive_compact_masking_kmac_certificate(&contract)?;
    let application_multiplicity = selected_application_multiplicity(scope)?;
    let hybrid_loss = certificate.quantum_hybrid_loss(application_multiplicity)?;
    enforce_selected_known_loss_floor(&hybrid_loss.known_loss_sum)?;
    Ok(CompactMaskingKmacConditionalHybridAccounting {
        selected_contract_source_hash,
        scope,
        hybrid_loss,
    })
}

fn derive_selected_compact_masking_kmac_certificate()
-> Result<CompactMaskingKmacCertificate, CompactMaskingKmacError> {
    let contract = CompactPublicKeyProofContract::decode_selected()?;
    derive_compact_masking_kmac_certificate(&contract)
}

fn derive_compact_masking_kmac_certificate(
    contract: &CompactPublicKeyProofContract,
) -> Result<CompactMaskingKmacCertificate, CompactMaskingKmacError> {
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
    let committed_leaf_salt_count = response_committed_leaf_salt_count;

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
    let leaf_salt_bytes = checked_product(
        committed_leaf_salt_count,
        u64::try_from(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH)
            .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?,
    )?;
    let block_byte_length = u64::try_from(PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH)
        .map_err(|_| CompactMaskingKmacError::ArithmeticOverflow)?;
    let minimum_construction_blocks = minimum_construction_bytes.div_ceil(block_byte_length);
    let maximum_construction_blocks = maximum_construction_bytes.div_ceil(block_byte_length);
    let leaf_salt_blocks = leaf_salt_bytes.div_ceil(block_byte_length);

    let coordinate_rows = [
        CompactMaskingKmacCoordinateRow {
            coordinate: CommonProofPrivateCoinCoordinate::hiding_argument(),
            operation: CompactMaskingPrivateCoinOperation::ModuloSamples {
                modulus: PROOF_BASE_FIELD_MODULUS,
                output_count: private_base_field_sample_count,
                maximum_candidate_draws_per_output:
                    SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
            },
            minimum_distinct_block_frame_count: minimum_construction_blocks,
            maximum_distinct_block_frame_count: maximum_construction_blocks,
        },
        CompactMaskingKmacCoordinateRow {
            coordinate: CommonProofPrivateCoinCoordinate::proof_salt(),
            operation: CompactMaskingPrivateCoinOperation::RawBytes {
                byte_count: leaf_salt_bytes,
            },
            minimum_distinct_block_frame_count: leaf_salt_blocks,
            maximum_distinct_block_frame_count: leaf_salt_blocks,
        },
    ];
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
            family: CompactMaskingKmacCallFamily::SetupAttempt,
            customization: SETUP_ATTEMPT_CUSTOMIZATION,
            key_bit_length: stream_key_bit_length,
            output_bit_length: KMAC256_ATTEMPT_IDENTIFIER_OUTPUT_BIT_LENGTH,
            minimum_call_count: 0,
            maximum_call_count: 0,
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
            family: CompactMaskingKmacCallFamily::OrdinaryProofAttempt,
            customization: ORDINARY_PROOF_ATTEMPT_CUSTOMIZATION,
            key_bit_length: proof_coin_key_bit_length,
            output_bit_length: KMAC256_ATTEMPT_IDENTIFIER_OUTPUT_BIT_LENGTH,
            minimum_call_count: 0,
            maximum_call_count: 0,
        },
        CompactMaskingKmacCallRow {
            family: CompactMaskingKmacCallFamily::TargetReleaseAttempt,
            customization: TARGET_RELEASE_ATTEMPT_CUSTOMIZATION,
            key_bit_length: stream_key_bit_length,
            output_bit_length: KMAC256_ATTEMPT_IDENTIFIER_OUTPUT_BIT_LENGTH,
            minimum_call_count: 0,
            maximum_call_count: 0,
        },
        CompactMaskingKmacCallRow {
            family: CompactMaskingKmacCallFamily::ConstructionMaskBlocks,
            customization: PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION,
            key_bit_length: stream_key_bit_length,
            output_bit_length: KMAC256_BLOCK_OUTPUT_BIT_LENGTH,
            minimum_call_count: minimum_construction_blocks,
            maximum_call_count: maximum_construction_blocks,
        },
        CompactMaskingKmacCallRow {
            family: CompactMaskingKmacCallFamily::SecretLeafSaltBlocks,
            customization: PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION,
            key_bit_length: stream_key_bit_length,
            output_bit_length: KMAC256_BLOCK_OUTPUT_BIT_LENGTH,
            minimum_call_count: leaf_salt_blocks,
            maximum_call_count: leaf_salt_blocks,
        },
    ];
    let certificate = CompactMaskingKmacCertificate {
        private_extension_element_count,
        private_base_field_sample_count,
        response_committed_leaf_salt_count,
        minimum_transported_leaf_salt_count,
        maximum_transported_leaf_salt_count,
        response_commitment_count,
        committed_leaf_salt_count,
        coordinate_rows,
        call_rows,
        framing: CompactMaskingKmacFraming::selected(),
    };
    certificate.validate()?;
    Ok(certificate)
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

fn selected_application_multiplicity(
    scope: CompactMaskingKmacUnionScope,
) -> Result<u64, CompactMaskingKmacError> {
    if scope == CompactMaskingKmacUnionScope::SinglePublicKeyShareProof {
        return Ok(1);
    }

    let inventory =
        super::selected_accounting::derive_selected_proof_family_application_inventory()
            .map_err(|_| CompactMaskingKmacError::InvalidCensus)?;
    let count = match scope {
        CompactMaskingKmacUnionScope::SinglePublicKeyShareProof => 1,
        CompactMaskingKmacUnionScope::SelectedPublicKeyShareRosterUnion => inventory
            .family_entry(
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            )
            .ok_or(CompactMaskingKmacError::InvalidCensus)?
            .physical_proof_application_count(),
        CompactMaskingKmacUnionScope::CompletePhysicalProofInventoryMultiplicity => inventory
            .total_physical_proof_application_count()
            .map_err(|_| CompactMaskingKmacError::InvalidCensus)?,
    };
    if count == 0 {
        return Err(CompactMaskingKmacError::InvalidCensus);
    }
    Ok(u64::from(count))
}

fn enforce_selected_known_loss_floor(
    known_loss: &ExactProbabilityUpperBound,
) -> Result<(), CompactMaskingKmacError> {
    if !known_loss.is_at_most_inverse_power_of_two(SELECTED_KNOWN_LOSS_SECURITY_BIT_FLOOR) {
        return Err(CompactMaskingKmacError::KnownLossAboveSelectedFloor);
    }
    Ok(())
}

fn qprf_key_term(
    key_role: CompactMaskingKmacKeyRole,
    key_bit_length: u32,
    fixed_customization_domain_count: u32,
    output_bit_lengths: Vec<u32>,
    key_instance_multiplicity: u64,
    honest_query_count_per_key: u64,
) -> CompactMaskingKmacQprfKeyTerm {
    CompactMaskingKmacQprfKeyTerm {
        key_role,
        key_bit_length,
        fixed_customization_domain_count,
        output_bit_lengths,
        key_instance_multiplicity,
        honest_query_count_per_key,
        reduction_query_bound_per_key: BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET)
            + BigUint::from(honest_query_count_per_key),
    }
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
        CanonicalDecodeLimits, CanonicalItemType, CanonicalTuple, ParticipantIdentity,
        PersistentProofCoinInput, PrivateRandomBlockInput, PrivateRandomnessDomain,
        ProofApplicationSlot, ProofApplicationSlotCeilings,
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

        let certificate = derive_selected_compact_masking_kmac_certificate()
            .expect("selected compact masking KMAC certificate");
        assert_eq!(certificate.private_extension_element_count, 230_488);
        assert_eq!(certificate.private_base_field_sample_count, 1_152_440);
        assert_eq!(certificate.committed_leaf_salt_count, 639_270);
        assert_eq!(certificate.response_committed_leaf_salt_count, 639_270);
        assert!(
            certificate.minimum_transported_leaf_salt_count
                < certificate.maximum_transported_leaf_salt_count
        );
        assert_eq!(certificate.maximum_transported_leaf_salt_count, 79_310);
        assert!(
            certificate.maximum_transported_leaf_salt_count
                < certificate.response_committed_leaf_salt_count
        );
        assert_eq!(certificate.response_commitment_count, 82);
        assert_eq!(
            certificate.coordinate_rows,
            [
                CompactMaskingKmacCoordinateRow {
                    coordinate: CommonProofPrivateCoinCoordinate::hiding_argument(),
                    operation: CompactMaskingPrivateCoinOperation::ModuloSamples {
                        modulus: PROOF_BASE_FIELD_MODULUS,
                        output_count: 1_152_440,
                        maximum_candidate_draws_per_output: 64,
                    },
                    minimum_distinct_block_frame_count: 144_055,
                    maximum_distinct_block_frame_count: 9_219_520,
                },
                CompactMaskingKmacCoordinateRow {
                    coordinate: CommonProofPrivateCoinCoordinate::proof_salt(),
                    operation: CompactMaskingPrivateCoinOperation::RawBytes {
                        byte_count: 81_826_560,
                    },
                    minimum_distinct_block_frame_count: 1_278_540,
                    maximum_distinct_block_frame_count: 1_278_540,
                },
            ],
        );
        assert!(matches!(
            certificate.coordinate_rows[0].operation,
            CompactMaskingPrivateCoinOperation::ModuloSamples { .. },
        ));
        assert!(matches!(
            certificate.coordinate_rows[1].operation,
            CompactMaskingPrivateCoinOperation::RawBytes { .. },
        ));
        assert_eq!(certificate.call_rows[0].output_bit_length, 1_536);
        assert_eq!(certificate.call_rows[1].maximum_call_count, 0);
        assert_eq!(certificate.call_rows[2].maximum_call_count, 1);
        assert_eq!(certificate.call_rows[3].maximum_call_count, 1);
        assert_eq!(certificate.call_rows[4].maximum_call_count, 0);
        assert_eq!(certificate.call_rows[5].maximum_call_count, 0);
        assert_eq!(certificate.call_rows[6].maximum_call_count, 9_219_520);
        assert_eq!(certificate.call_rows[7].maximum_call_count, 1_278_540);
        assert_eq!(certificate.framing, CompactMaskingKmacFraming::selected());
        let framing = certificate.framing;
        assert_eq!(
            (
                framing.proof_family_schema_identifier,
                framing.attempt_authority,
                framing.persistent_input_schema_identifier,
                framing.preparation_customization,
                framing.witness_attempt_customization,
                framing.witness_part_length_prefix_byte_length,
                framing.coordinate_context_hash_domain,
                framing.coordinate_context_parts,
            ),
            (
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                CompactMaskingProofAttemptAuthority::PersistentResetSafeCanonicalWitness,
                PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER,
                PERSISTENT_PROOF_PREPARATION_CUSTOMIZATION,
                PERSISTENT_PROOF_WITNESS_ATTEMPT_CUSTOMIZATION,
                8,
                COMMON_PROOF_PRIVATE_COIN_COORDINATE_HASH_DOMAIN,
                [
                    CompactMaskingCoordinateContextPart::DerivationBindingHash512,
                    CompactMaskingCoordinateContextPart::PurposeClassU16LittleEndian,
                    CompactMaskingCoordinateContextPart::OrdinalU32LittleEndian,
                ],
            ),
        );
        assert_eq!(
            (
                framing.distinct_coordinate_context_input_count_per_application,
                framing.distinct_stream_attempt_input_count_per_application,
                framing.block_customization,
                framing.block_input_schema_identifier,
                framing.block_input_schema_version,
                framing.block_input_fields,
            ),
            (
                2,
                1,
                PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION,
                PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER,
                PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_VERSION,
                [
                    CompactMaskingBlockFrameField::ProtocolVersionU16,
                    CompactMaskingBlockFrameField::SuiteIdentifierHash512,
                    CompactMaskingBlockFrameField::CeremonyContextHash512,
                    CompactMaskingBlockFrameField::ActionContextHash512,
                    CompactMaskingBlockFrameField::ParticipantIdentity,
                    CompactMaskingBlockFrameField::ProofFamilyU16,
                    CompactMaskingBlockFrameField::PurposeClassU16,
                    CompactMaskingBlockFrameField::CoordinateContextHash512,
                    CompactMaskingBlockFrameField::AttemptIdentifierBytes32,
                    CompactMaskingBlockFrameField::BlockCounterU64,
                ],
            ),
        );
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
            assert_eq!(accounting.scope, scope);
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
    fn quantum_hybrid_charges_both_symbolic_qprf_hops() {
        let certificate = derive_selected_compact_masking_kmac_certificate()
            .expect("selected compact masking KMAC certificate");
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
        assert_eq!(
            quantum.leaf_salt_collision.numerator,
            choose_two(10 * certificate.committed_leaf_salt_count),
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
            ],
        );
        assert_eq!(quantum.qprf_hops[0].key_terms.len(), 1);
        assert_eq!(quantum.qprf_hops[1].key_terms.len(), 2);
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
        assert_eq!(stream.honest_query_count_per_key, 10_498_060,);
        assert_eq!(
            stream.reduction_query_bound_per_key,
            BigUint::from(DECLARED_ADVERSARIAL_QUERY_BUDGET) + BigUint::from(10_498_060_u64),
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
