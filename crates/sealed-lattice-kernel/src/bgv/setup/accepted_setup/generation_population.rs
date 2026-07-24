use std::rc::Rc;

use zeroize::Zeroizing;

use crate::{
    bgv::{
        evaluator::key_switch::special_basis_modulus_residue,
        key_switch_topology::canonical_residue_byte_length,
        modular_arithmetic::{add_mod_fast, mul_mod_fast, sub_mod_fast},
        parameters::PLAINTEXT_MODULUS,
        proof_suite::{
            CommittedMaterialContext, CommittedMaterialRole, CommittedMaterialTree,
            KeySwitchComponentMaterialTopology, RecipientShareLimbInput,
            SelectedEvaluatorEntryKind, apply_negacyclic_automorphism,
            canonical_recipient_private_vss_payload, selected_committed_material_profile,
            selected_committed_material_relation_plan_input,
            selected_evaluator_galois_entry_positions, selected_galois_key_share_batch_schedule,
            selected_public_key_share_relation_plan_input,
        },
        setup::{
            SETUP_COMMITMENT_HIDING_ERROR_WIDTH, SETUP_COMMITMENT_HIDING_SECRET_WIDTH,
            SETUP_COMMITMENT_MODULUS_LIMB_INDICES, compute_lattice_anchor_commitment,
            lattice_anchor_commitment_canonical_bytes,
            sample_collective_public_key_common_reference_limb,
            sample_galois_common_reference_limb,
        },
    },
    foundation::{
        ActionPrivateRandomness, CanonicalItem, CanonicalTuple, FOUNDATION_PROFILE, Hash512,
        PrivateRandomnessAttemptIdentifier, PrivateRandomnessDomain, RefusalReason,
        SelectedSuiteCapability, SetupStructuredCommitmentOpeningContext, StateCapabilityKind,
        VerifiedStateReservationRuntimeBinding, hash_foundation_tuple_512,
    },
    transcript_core::encode_hex,
};

use super::{
    VerifiedPublicRandomness,
    generation_authority::{
        SetupGeneratedCommittedMaterial, SetupGeneratedGaloisEntry,
        SetupGeneratedKeySwitchComponent, SetupGeneratedPublicKeyShare,
        SetupGeneratedRecipientPrivateVssPayload, SetupGeneratedVssMaterial,
        SetupGenerationAnchorOpening, SetupGenerationAuthorityHandle,
        SetupGenerationAuthorityInput, retain_browser_owned_setup_generation_authority,
    },
    generation_relinearization::construct_relinearization_material,
};
use crate::bgv::setup::sampling::negacyclic_product_mod;

#[cfg(all(feature = "proof-backend-bakeoff", not(target_arch = "wasm32")))]
use super::verified_public_randomness::VerifiedSetupVerificationContext;

#[cfg(all(feature = "proof-backend-bakeoff", not(target_arch = "wasm32")))]
use crate::foundation::{
    ACTION_RANDOMNESS_ROOT_BYTE_LENGTH, ActionRandomnessDerivationInput, ActionRandomnessRoot,
    ParticipantIdentity, StateDurableBinding, selected_suite_capability_for_tests,
};

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const SETUP_SOURCE_SAMPLER_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x120c;
const GALOIS_ERROR_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x120e;
const PUBLIC_KEY_ERROR_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x120f;
const SETUP_SOURCE_SAMPLER_CONTEXT_HASH_DOMAIN: &str =
    "sealed-lattice/setup/private-sampler-context/v1";
const GALOIS_ERROR_CONTEXT_HASH_DOMAIN: &str = "sealed-lattice/setup/galois-error-context/v1";
const PUBLIC_KEY_ERROR_CONTEXT_HASH_DOMAIN: &str =
    "sealed-lattice/setup/public-key-error-context/v1";
const SECRET_CONTRIBUTION_DISTRIBUTION_PURPOSE: u16 = 1;
const PUBLIC_KEY_ERROR_DISTRIBUTION_PURPOSE: u16 = 2;
const GALOIS_ERROR_DISTRIBUTION_PURPOSE: u16 = 7;
const ANCHOR_HIDING_SECRET_DISTRIBUTION_PURPOSE: u16 = 11;
const ANCHOR_HIDING_ERROR_DISTRIBUTION_PURPOSE: u16 = 12;
const COEFFICIENT_MATERIAL_SEED_PURPOSE: u16 = 1;
const RECIPIENT_SHARE_MATERIAL_SEED_PURPOSE: u16 = 2;
const NONCONSTANT_VSS_COEFFICIENT_PURPOSE: u16 = 4;
const DATA_MODULUS_CATALOG_IDENTIFIER: u16 = 1;
const SPECIAL_MODULUS_CATALOG_IDENTIFIER: u16 = 2;
const GALOIS_ERROR_CENTERED_BINOMIAL_PARAMETER: u16 = 2;
const PUBLIC_KEY_ERROR_CENTERED_BINOMIAL_PARAMETER: u16 = 2;
const MATERIAL_SEED_BYTE_LENGTH: usize = 64;

struct SetupGenerationBindings {
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    ordered_roster: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    roster_position: u16,
    setup_attempt_identifier: PrivateRandomnessAttemptIdentifier,
    action_randomness_authorization_hash: [u8; Hash512::BYTE_LENGTH],
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
}

struct RecipientPayloadLimb {
    sharing_limb_index: u16,
    canonical_share_coefficients: Zeroizing<Vec<u64>>,
    recipient_share_material_seed: Zeroizing<[u8; MATERIAL_SEED_BYTE_LENGTH]>,
}

#[cfg(all(feature = "proof-backend-bakeoff", not(target_arch = "wasm32")))]
pub(crate) struct ProductionBackendPrototypeAuthority {
    pub(crate) action_private_randomness: Rc<ActionPrivateRandomness>,
    pub(crate) authority_handle: SetupGenerationAuthorityHandle,
}

#[cfg(all(feature = "proof-backend-bakeoff", not(target_arch = "wasm32")))]
pub(crate) fn populate_production_backend_prototype_authority()
-> Result<ProductionBackendPrototypeAuthority, RefusalReason> {
    let selected_suite = selected_suite_capability_for_tests();
    let suite_identifier = Hash512::from_bytes(selected_suite.suite_identifier());
    let manifest_hash = Hash512::from_bytes([0x21; Hash512::BYTE_LENGTH]);
    let ceremony_context_hash = Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]);
    let action_context_hash = Hash512::from_bytes([0x23; Hash512::BYTE_LENGTH]);
    let roster_hash = Hash512::from_bytes([0x24; Hash512::BYTE_LENGTH]);
    let public_setup_seed = Hash512::from_bytes([0x25; Hash512::BYTE_LENGTH]);
    let local_roster_position = 3_usize;
    let ordered_participant_identities = (0..usize::from(FOUNDATION_PROFILE.participant_count))
        .map(|participant_index| {
            let mut bytes = [0x31; Hash512::BYTE_LENGTH];
            bytes[..8].copy_from_slice(&(participant_index as u64).to_le_bytes());
            ParticipantIdentity::from_bytes(bytes)
        })
        .collect::<Vec<_>>();
    let local_participant_identity = ordered_participant_identities[local_roster_position];
    let action_private_randomness = Rc::new(
        ActionRandomnessRoot::from_injected_bytes(Zeroizing::new(
            [0x5a; ACTION_RANDOMNESS_ROOT_BYTE_LENGTH],
        ))
        .derive(ActionRandomnessDerivationInput::new(
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            local_participant_identity,
        ))
        .map_err(|error| error.refusal_reason)?,
    );
    let mut ordered_action_randomness_commitments = (0..ordered_participant_identities.len())
        .map(|participant_index| {
            let mut bytes = [0x32; Hash512::BYTE_LENGTH];
            bytes[..8].copy_from_slice(&(participant_index as u64).to_le_bytes());
            Hash512::from_bytes(bytes)
        })
        .collect::<Vec<_>>();
    ordered_action_randomness_commitments[local_roster_position] =
        action_private_randomness.action_randomness_commitment();
    let verified_public_randomness =
        VerifiedPublicRandomness::from_production_backend_prototype_values(
            VerifiedSetupVerificationContext::for_production_backend_prototype(
                suite_identifier,
                manifest_hash,
                ceremony_context_hash,
                action_context_hash,
                roster_hash,
            ),
            ordered_participant_identities,
            ordered_action_randomness_commitments,
            public_setup_seed,
        )?;
    let authorization_hash = action_private_randomness
        .setup_action_randomness_authorization(roster_hash)
        .map_err(|error| error.refusal_reason)?;
    let verified_reservation_binding = VerifiedStateReservationRuntimeBinding {
        authorization_hash,
        durable_binding: StateDurableBinding::for_production_backend_prototype(
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            local_participant_identity,
        ),
    };
    let authority_handle = populate_browser_owned_setup_generation_authority(
        &selected_suite,
        &verified_public_randomness,
        Rc::clone(&action_private_randomness),
        verified_reservation_binding,
    )?;
    Ok(ProductionBackendPrototypeAuthority {
        action_private_randomness,
        authority_handle,
    })
}

/// Constructs the complete browser-owned setup-generation authority from
/// positively verified inputs. No witness value, root, trace row, material
/// seed, participant coordinate, or evaluator component is accepted from the
/// JavaScript boundary.
pub(in crate::bgv) fn populate_browser_owned_setup_generation_authority(
    selected_suite: &SelectedSuiteCapability,
    verified_public_randomness: &VerifiedPublicRandomness,
    action_private_randomness: Rc<ActionPrivateRandomness>,
    verified_reservation_binding: VerifiedStateReservationRuntimeBinding,
) -> Result<SetupGenerationAuthorityHandle, RefusalReason> {
    let bindings = validate_setup_generation_bindings(
        selected_suite,
        verified_public_randomness,
        &action_private_randomness,
        verified_reservation_binding,
    )?;
    let relation_input = selected_committed_material_relation_plan_input()
        .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
    let ring_degree = usize::try_from(relation_input.ring_degree)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    if u64::from(selected_suite.polynomial_degree()) != relation_input.ring_degree
        || relation_input.participant_count != FOUNDATION_PROFILE.participant_count
        || relation_input.threshold != FOUNDATION_PROFILE.reconstruction_threshold
    {
        return Err(RefusalReason::UnsupportedVersionOrSuite);
    }

    let common_secret_coefficients = sample_common_secret_coefficients(
        selected_suite,
        &action_private_randomness,
        bindings.source_setup_intent_object_hash,
        bindings.setup_attempt_identifier,
        ring_degree,
    )?;
    let (anchor_commitment_roots, anchor_openings) = construct_anchor_openings(
        selected_suite,
        &action_private_randomness,
        &bindings,
        &common_secret_coefficients,
        usize::try_from(relation_input.evaluation_domain_size)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
    )?;
    let vss_material = construct_vss_material(
        selected_suite,
        &action_private_randomness,
        &bindings,
        &common_secret_coefficients,
    )?;
    let public_key_share = construct_public_key_share(
        selected_suite,
        &action_private_randomness,
        &bindings,
        &common_secret_coefficients,
        usize::try_from(relation_input.evaluation_domain_size)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
    )?;
    let relinearization_material = construct_relinearization_material(
        selected_suite,
        &action_private_randomness,
        bindings.source_setup_intent_object_hash,
        bindings.setup_attempt_identifier,
        bindings.public_setup_seed,
        &common_secret_coefficients,
    )?;
    let ordered_galois_entries = construct_galois_entries(
        selected_suite,
        &action_private_randomness,
        &bindings,
        &common_secret_coefficients,
    )?;
    let [galois_batch_schedule_position] = selected_galois_key_share_batch_schedule();

    retain_browser_owned_setup_generation_authority(SetupGenerationAuthorityInput {
        suite_identifier: bindings.suite_identifier,
        manifest_hash: bindings.manifest_hash,
        ceremony_context_hash: bindings.ceremony_context_hash,
        action_context_hash: bindings.action_context_hash,
        roster_hash: bindings.roster_hash,
        ordered_roster: bindings.ordered_roster,
        setup_proof_context_hash: bindings.setup_proof_context_hash,
        source_setup_intent_object_hash: bindings.source_setup_intent_object_hash,
        participant_identity: bindings.participant_identity,
        roster_position: bindings.roster_position,
        setup_attempt_identifier: *bindings.setup_attempt_identifier.as_bytes(),
        action_randomness_authorization_hash: bindings.action_randomness_authorization_hash,
        action_private_randomness,
        public_setup_seed: bindings.public_setup_seed,
        anchor_commitment_roots,
        anchor_openings,
        common_secret_coefficients,
        public_key_share,
        vss_material,
        relinearization_material,
        galois_batch_schedule_position,
        ordered_galois_entries,
    })
}

fn construct_public_key_share(
    selected_suite: &SelectedSuiteCapability,
    action_private_randomness: &ActionPrivateRandomness,
    bindings: &SetupGenerationBindings,
    common_secret_coefficients: &[i8],
    evaluation_domain_size: usize,
) -> Result<SetupGeneratedPublicKeyShare, RefusalReason> {
    let relation_input = selected_public_key_share_relation_plan_input()
        .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
    let ring_degree = usize::try_from(relation_input.ring_degree)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    if common_secret_coefficients.len() != ring_degree {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let error_context_hash =
        public_key_error_context_hash(bindings.source_setup_intent_object_hash)?;
    let centered_error_coefficients = sample_centered_binomial_polynomial(
        action_private_randomness,
        PrivateRandomnessDomain::setup_suite_distribution(PUBLIC_KEY_ERROR_DISTRIBUTION_PURPOSE)
            .map_err(|error| error.refusal_reason)?,
        error_context_hash,
        bindings.setup_attempt_identifier,
        PUBLIC_KEY_ERROR_CENTERED_BINOMIAL_PARAMETER,
        ring_degree,
    )?;
    let mut ordered_limb_coefficients =
        Vec::with_capacity(relation_input.data_modulus_indices.len());
    for data_modulus_index in relation_input.data_modulus_indices.iter().copied() {
        let modulus = *selected_suite
            .ordered_data_primes()
            .get(usize::from(data_modulus_index))
            .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        let common_reference = sample_collective_public_key_common_reference_limb(
            &bindings.public_setup_seed,
            data_modulus_index,
            ring_degree,
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        ordered_limb_coefficients.push(construct_public_key_share_limb(
            &common_reference,
            common_secret_coefficients,
            &centered_error_coefficients,
            modulus,
        )?);
    }
    SetupGeneratedPublicKeyShare::from_browser_owned_witness(
        bindings.setup_proof_context_hash,
        bindings.participant_identity,
        bindings.roster_position,
        evaluation_domain_size,
        ring_degree,
        relation_input.data_modulus_indices,
        ordered_limb_coefficients,
        centered_error_coefficients,
    )
}

fn construct_public_key_share_limb(
    common_reference: &[u64],
    common_secret_coefficients: &[i8],
    centered_error_coefficients: &[i8],
    modulus: u64,
) -> Result<Zeroizing<Vec<u64>>, RefusalReason> {
    if common_reference.is_empty()
        || common_reference.len() != common_secret_coefficients.len()
        || common_reference.len() != centered_error_coefficients.len()
        || common_reference
            .iter()
            .any(|coefficient| *coefficient >= modulus)
        || common_secret_coefficients
            .iter()
            .any(|coefficient| !(-1..=1).contains(coefficient))
        || centered_error_coefficients
            .iter()
            .any(|coefficient| !(-2..=2).contains(coefficient))
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let secret_residues = Zeroizing::new(
        common_secret_coefficients
            .iter()
            .copied()
            .map(|coefficient| centered_i8_residue(coefficient, modulus))
            .collect::<Vec<_>>(),
    );
    let common_reference_secret_product = Zeroizing::new(
        negacyclic_product_mod(common_reference, &secret_residues, modulus)
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
    );
    Ok(Zeroizing::new(
        centered_error_coefficients
            .iter()
            .copied()
            .zip(common_reference_secret_product.iter().copied())
            .map(|(error, product)| {
                sub_mod_fast(
                    mul_mod_fast(
                        PLAINTEXT_MODULUS % modulus,
                        centered_i32_residue(i32::from(error), modulus),
                        modulus,
                    ),
                    product,
                    modulus,
                )
            })
            .collect::<Vec<_>>(),
    ))
}

fn validate_setup_generation_bindings(
    selected_suite: &SelectedSuiteCapability,
    verified_public_randomness: &VerifiedPublicRandomness,
    action_private_randomness: &ActionPrivateRandomness,
    verified_reservation_binding: VerifiedStateReservationRuntimeBinding,
) -> Result<SetupGenerationBindings, RefusalReason> {
    let context = verified_public_randomness.context();
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let derivation_input = action_private_randomness.derivation_input();
    let participant_identity = derivation_input.participant_identity();
    let matching_roster_positions = verified_public_randomness
        .ordered_participant_identities()
        .iter()
        .enumerate()
        .filter_map(|(roster_position, roster_participant)| {
            (*roster_participant == participant_identity).then_some(roster_position)
        })
        .collect::<Vec<_>>();
    let [roster_position] = matching_roster_positions.as_slice() else {
        return Err(RefusalReason::WrongContext);
    };
    let roster_position =
        u16::try_from(*roster_position).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let action_randomness_commitment = action_private_randomness.action_randomness_commitment();
    let durable_binding = verified_reservation_binding.durable_binding;
    let expected_authorization_hash = action_private_randomness
        .setup_action_randomness_authorization(context.roster_hash())
        .map_err(|error| error.refusal_reason)?;

    if selected_suite.protocol_version() != context.protocol_version()
        || selected_suite.suite_identifier() != context.suite_identifier().into_bytes()
        || derivation_input.suite_identifier() != context.suite_identifier()
        || derivation_input.ceremony_context_hash() != context.ceremony_context_hash()
        || derivation_input.action_context_hash() != context.action_context_hash()
        || verified_public_randomness
            .ordered_participant_identities()
            .len()
            != participant_count
        || verified_public_randomness
            .ordered_setup_intent_object_hashes()
            .len()
            != participant_count
        || verified_public_randomness
            .ordered_action_randomness_commitments()
            .len()
            != participant_count
        || verified_public_randomness.ordered_action_randomness_commitments()
            [usize::from(roster_position)]
            != action_randomness_commitment
        || durable_binding.capability_kind() != StateCapabilityKind::SetupActionRandomnessRoot
        || durable_binding.suite_id() != context.suite_identifier()
        || durable_binding.ceremony_context_hash() != context.ceremony_context_hash()
        || durable_binding.action_context_hash() != context.action_context_hash()
        || durable_binding.subject_participant_id() != participant_identity
        || verified_reservation_binding.authorization_hash != expected_authorization_hash
    {
        return Err(RefusalReason::WrongContext);
    }

    Ok(SetupGenerationBindings {
        suite_identifier: context.suite_identifier().into_bytes(),
        manifest_hash: context.manifest_hash().into_bytes(),
        ceremony_context_hash: context.ceremony_context_hash().into_bytes(),
        action_context_hash: context.action_context_hash().into_bytes(),
        roster_hash: context.roster_hash().into_bytes(),
        ordered_roster: verified_public_randomness
            .ordered_participant_identities()
            .iter()
            .copied()
            .map(|identity| identity.into_bytes())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        setup_proof_context_hash: verified_public_randomness
            .setup_proof_context_hash()
            .into_bytes(),
        source_setup_intent_object_hash: verified_public_randomness
            .ordered_setup_intent_object_hashes()[usize::from(roster_position)]
        .into_bytes(),
        participant_identity: participant_identity.into_bytes(),
        roster_position,
        setup_attempt_identifier: action_private_randomness.setup_attempt_identifier(),
        action_randomness_authorization_hash: expected_authorization_hash.into_bytes(),
        public_setup_seed: verified_public_randomness.public_setup_seed().into_bytes(),
    })
}

fn sample_common_secret_coefficients(
    selected_suite: &SelectedSuiteCapability,
    action_private_randomness: &ActionPrivateRandomness,
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    setup_attempt_identifier: PrivateRandomnessAttemptIdentifier,
    ring_degree: usize,
) -> Result<Zeroizing<Vec<i8>>, RefusalReason> {
    let context_hash = setup_source_sampler_context_hash(source_setup_intent_object_hash)?;
    sample_centered_ternary_polynomial(
        selected_suite,
        action_private_randomness,
        PrivateRandomnessDomain::setup_suite_distribution(SECRET_CONTRIBUTION_DISTRIBUTION_PURPOSE)
            .map_err(|error| error.refusal_reason)?,
        context_hash,
        setup_attempt_identifier,
        ring_degree,
    )
}

fn construct_anchor_openings(
    selected_suite: &SelectedSuiteCapability,
    action_private_randomness: &ActionPrivateRandomness,
    bindings: &SetupGenerationBindings,
    common_secret_coefficients: &[i8],
    evaluation_domain_size: usize,
) -> Result<
    (
        [[u8; Hash512::BYTE_LENGTH]; 3],
        Vec<SetupGenerationAnchorOpening>,
    ),
    RefusalReason,
> {
    let mut anchor_commitment_roots = [[0_u8; Hash512::BYTE_LENGTH]; 3];
    let mut anchor_openings = Vec::with_capacity(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len());
    let public_setup_seed_hex = encode_hex(&bindings.public_setup_seed);
    for (anchor_ordinal, commitment_data_prime_index) in SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .into_iter()
        .enumerate()
    {
        let commitment_data_prime_index = u16::try_from(commitment_data_prime_index)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let mut hiding_secret_polynomials =
            Vec::with_capacity(SETUP_COMMITMENT_HIDING_SECRET_WIDTH);
        for component_ordinal in 0..SETUP_COMMITMENT_HIDING_SECRET_WIDTH {
            let opening_context = SetupStructuredCommitmentOpeningContext::new(
                Hash512::from_bytes(bindings.source_setup_intent_object_hash),
                commitment_data_prime_index,
                ANCHOR_HIDING_SECRET_DISTRIBUTION_PURPOSE,
                u16::try_from(component_ordinal)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .map_err(|error| error.refusal_reason)?;
            hiding_secret_polynomials.push(sample_centered_ternary_polynomial(
                selected_suite,
                action_private_randomness,
                PrivateRandomnessDomain::setup_suite_distribution(
                    ANCHOR_HIDING_SECRET_DISTRIBUTION_PURPOSE,
                )
                .map_err(|error| error.refusal_reason)?,
                opening_context
                    .hash()
                    .map_err(|error| error.refusal_reason)?,
                bindings.setup_attempt_identifier,
                common_secret_coefficients.len(),
            )?);
        }
        let mut hiding_error_polynomials = Vec::with_capacity(SETUP_COMMITMENT_HIDING_ERROR_WIDTH);
        for component_ordinal in 0..SETUP_COMMITMENT_HIDING_ERROR_WIDTH {
            let opening_context = SetupStructuredCommitmentOpeningContext::new(
                Hash512::from_bytes(bindings.source_setup_intent_object_hash),
                commitment_data_prime_index,
                ANCHOR_HIDING_ERROR_DISTRIBUTION_PURPOSE,
                u16::try_from(component_ordinal)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .map_err(|error| error.refusal_reason)?;
            hiding_error_polynomials.push(sample_centered_ternary_polynomial(
                selected_suite,
                action_private_randomness,
                PrivateRandomnessDomain::setup_suite_distribution(
                    ANCHOR_HIDING_ERROR_DISTRIBUTION_PURPOSE,
                )
                .map_err(|error| error.refusal_reason)?,
                opening_context
                    .hash()
                    .map_err(|error| error.refusal_reason)?,
                bindings.setup_attempt_identifier,
                common_secret_coefficients.len(),
            )?);
        }
        let commitment = compute_lattice_anchor_commitment(
            &public_setup_seed_hex,
            usize::from(commitment_data_prime_index),
            common_secret_coefficients,
            &[
                hiding_secret_polynomials[0].as_slice(),
                hiding_secret_polynomials[1].as_slice(),
                hiding_error_polynomials[0].as_slice(),
            ],
        )
        .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
        let canonical_commitment_bytes = lattice_anchor_commitment_canonical_bytes(&commitment)
            .map_err(|_| RefusalReason::MalformedEncoding)?;
        let opening = SetupGenerationAnchorOpening::from_browser_owned_witness(
            bindings.setup_proof_context_hash,
            bindings.participant_identity,
            bindings.roster_position,
            commitment_data_prime_index,
            evaluation_domain_size,
            canonical_commitment_bytes,
            hiding_secret_polynomials,
            hiding_error_polynomials,
        )?;
        anchor_commitment_roots[anchor_ordinal] = opening.root();
        anchor_openings.push(opening);
    }
    Ok((anchor_commitment_roots, anchor_openings))
}

fn construct_vss_material(
    selected_suite: &SelectedSuiteCapability,
    action_private_randomness: &ActionPrivateRandomness,
    bindings: &SetupGenerationBindings,
    common_secret_coefficients: &[i8],
) -> Result<SetupGeneratedVssMaterial, RefusalReason> {
    let relation_input = selected_committed_material_relation_plan_input()
        .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
    let committed_material_profile = selected_committed_material_profile()
        .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
    let participant_count = usize::from(relation_input.participant_count);
    let threshold = usize::from(relation_input.threshold);
    let ring_degree = usize::try_from(relation_input.ring_degree)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let point_stride = relation_input
        .point_stride()
        .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
    if common_secret_coefficients.len() != ring_degree {
        return Err(RefusalReason::WrongTypeOrLength);
    }

    let coefficient_material_count = relation_input
        .sharing_data_modulus_indices
        .len()
        .checked_mul(threshold)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let recipient_material_count = relation_input
        .sharing_data_modulus_indices
        .len()
        .checked_mul(participant_count)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let mut ordered_coefficient_materials = Vec::with_capacity(coefficient_material_count);
    let mut ordered_recipient_share_materials = Vec::with_capacity(recipient_material_count);
    let mut recipient_payload_limbs = (0..participant_count)
        .map(|_| Vec::with_capacity(relation_input.sharing_data_modulus_indices.len()))
        .collect::<Vec<_>>();

    for sharing_limb_index in relation_input.sharing_data_modulus_indices.iter().copied() {
        let modulus = selected_suite
            .ordered_data_primes()
            .get(usize::from(sharing_limb_index))
            .copied()
            .ok_or(RefusalReason::UnsupportedVersionOrSuite)?;
        let mut sharing_coefficients = Vec::with_capacity(threshold);
        sharing_coefficients.push(Zeroizing::new(
            common_secret_coefficients
                .iter()
                .copied()
                .map(|coefficient| centered_i8_residue(coefficient, modulus))
                .collect::<Vec<_>>(),
        ));
        for coefficient_index in 1..threshold {
            let material_context = CommittedMaterialContext::new(
                bindings.suite_identifier,
                bindings.ceremony_context_hash,
                bindings.action_context_hash,
                bindings.participant_identity,
                CommittedMaterialRole::Coefficient,
                sharing_limb_index,
                u16::try_from(coefficient_index)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            );
            let material_context_hash = material_context
                .context_hash()
                .map_err(|_| RefusalReason::WrongContext)?;
            sharing_coefficients.push(sample_uniform_polynomial(
                selected_suite,
                action_private_randomness,
                PrivateRandomnessDomain::vss_expansion(NONCONSTANT_VSS_COEFFICIENT_PURPOSE)
                    .map_err(|error| error.refusal_reason)?,
                Hash512::from_bytes(material_context_hash),
                bindings.setup_attempt_identifier,
                modulus,
                ring_degree,
            )?);
        }

        for (coefficient_index, coefficients) in sharing_coefficients.iter().enumerate() {
            let material_context = CommittedMaterialContext::new(
                bindings.suite_identifier,
                bindings.ceremony_context_hash,
                bindings.action_context_hash,
                bindings.participant_identity,
                CommittedMaterialRole::Coefficient,
                sharing_limb_index,
                u16::try_from(coefficient_index)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            );
            let material_context_hash = material_context
                .context_hash()
                .map_err(|_| RefusalReason::WrongContext)?;
            let material_seed = sample_material_seed(
                action_private_randomness,
                COEFFICIENT_MATERIAL_SEED_PURPOSE,
                material_context_hash,
                bindings.setup_attempt_identifier,
            )?;
            ordered_coefficient_materials.push(construct_committed_material(
                committed_material_profile,
                material_context_hash,
                *material_seed,
                coefficients,
                modulus,
            )?);
        }

        for (recipient_roster_position, recipient_payload_limb_list) in
            recipient_payload_limbs.iter_mut().enumerate()
        {
            let canonical_share_coefficients = evaluate_recipient_share(
                &sharing_coefficients,
                recipient_roster_position,
                point_stride,
                modulus,
            )?;
            let recipient_roster_position_u16 = u16::try_from(recipient_roster_position)
                .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let material_context = CommittedMaterialContext::new(
                bindings.suite_identifier,
                bindings.ceremony_context_hash,
                bindings.action_context_hash,
                bindings.participant_identity,
                CommittedMaterialRole::RecipientShare,
                sharing_limb_index,
                recipient_roster_position_u16,
            );
            let material_context_hash = material_context
                .context_hash()
                .map_err(|_| RefusalReason::WrongContext)?;
            let material_seed = sample_material_seed(
                action_private_randomness,
                RECIPIENT_SHARE_MATERIAL_SEED_PURPOSE,
                material_context_hash,
                bindings.setup_attempt_identifier,
            )?;
            ordered_recipient_share_materials.push(construct_committed_material(
                committed_material_profile,
                material_context_hash,
                *material_seed,
                &canonical_share_coefficients,
                modulus,
            )?);
            recipient_payload_limb_list.push(RecipientPayloadLimb {
                sharing_limb_index,
                canonical_share_coefficients,
                recipient_share_material_seed: material_seed,
            });
        }
    }

    let mut recipient_private_payloads = Vec::with_capacity(participant_count);
    for (recipient_roster_position, payload_limbs) in
        recipient_payload_limbs.into_iter().enumerate()
    {
        let borrowed_payload_limbs = payload_limbs
            .iter()
            .map(|limb| RecipientShareLimbInput {
                sharing_limb_index: limb.sharing_limb_index,
                canonical_share_coefficients: &limb.canonical_share_coefficients,
                recipient_share_material_seed: &limb.recipient_share_material_seed,
            })
            .collect::<Vec<_>>();
        let recipient_roster_position = u16::try_from(recipient_roster_position)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let canonical_bytes = canonical_recipient_private_vss_payload(
            recipient_roster_position,
            &borrowed_payload_limbs,
        )
        .map_err(|_| RefusalReason::MalformedEncoding)?;
        recipient_private_payloads.push(
            SetupGeneratedRecipientPrivateVssPayload::from_canonical_bytes(
                recipient_roster_position,
                canonical_bytes,
            )?,
        );
    }

    SetupGeneratedVssMaterial::from_browser_owned_material(
        ordered_coefficient_materials,
        ordered_recipient_share_materials,
        recipient_private_payloads,
    )
}

fn construct_committed_material(
    committed_material_profile: crate::bgv::proof_suite::CommittedMaterialProfile,
    material_context_hash: [u8; Hash512::BYTE_LENGTH],
    material_seed: [u8; MATERIAL_SEED_BYTE_LENGTH],
    canonical_message: &[u64],
    canonical_modulus: u64,
) -> Result<SetupGeneratedCommittedMaterial, RefusalReason> {
    let tree = CommittedMaterialTree::from_canonical_message(
        committed_material_profile,
        material_context_hash,
        material_seed,
        canonical_message,
        canonical_modulus,
    )
    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
    SetupGeneratedCommittedMaterial::from_recomputed_tree_and_canonical_message(
        tree,
        Zeroizing::new(canonical_message.to_vec().into_boxed_slice()),
        canonical_modulus,
    )
}

fn construct_galois_entries(
    selected_suite: &SelectedSuiteCapability,
    action_private_randomness: &ActionPrivateRandomness,
    bindings: &SetupGenerationBindings,
    common_secret_coefficients: &[i8],
) -> Result<Vec<SetupGeneratedGaloisEntry>, RefusalReason> {
    let evaluator_positions = selected_evaluator_galois_entry_positions()
        .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
    let ring_degree = usize::try_from(selected_suite.polynomial_degree())
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    if common_secret_coefficients.len() != ring_degree {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let common_secret_i64 = Zeroizing::new(
        common_secret_coefficients
            .iter()
            .copied()
            .map(i64::from)
            .collect::<Vec<_>>(),
    );
    let mut ordered_entries = Vec::with_capacity(evaluator_positions.len());
    for evaluator_position in evaluator_positions {
        let SelectedEvaluatorEntryKind::Galois {
            galois_element,
            catalog_level,
        } = evaluator_position.key_kind()
        else {
            return Err(RefusalReason::WrongTypeOrLength);
        };
        let topology = KeySwitchComponentMaterialTopology::from_selected_suite_at_level(
            selected_suite,
            catalog_level,
        )?;
        let mut centered_error_polynomials_by_block =
            Vec::with_capacity(topology.data_block_count());
        for decomposition_block_index in 0..topology.data_block_count() {
            let context_hash = galois_error_context_hash(
                bindings.source_setup_intent_object_hash,
                evaluator_position.schedule_position(),
                u16::try_from(decomposition_block_index)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )?;
            centered_error_polynomials_by_block.push(sample_centered_binomial_polynomial(
                action_private_randomness,
                PrivateRandomnessDomain::setup_suite_distribution(
                    GALOIS_ERROR_DISTRIBUTION_PURPOSE,
                )
                .map_err(|error| error.refusal_reason)?,
                context_hash,
                bindings.setup_attempt_identifier,
                GALOIS_ERROR_CENTERED_BINOMIAL_PARAMETER,
                ring_degree,
            )?);
        }
        let automorphed_secret = Zeroizing::new(
            apply_negacyclic_automorphism(
                &common_secret_i64,
                u64::try_from(galois_element)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
        );
        let canonical_component_bytes = construct_galois_component_bytes(
            selected_suite,
            &topology,
            evaluator_position.schedule_position(),
            catalog_level,
            common_secret_coefficients,
            &automorphed_secret,
            &centered_error_polynomials_by_block,
            &bindings.public_setup_seed,
        )?;
        let component = SetupGeneratedKeySwitchComponent::from_canonical_bytes(
            evaluator_position,
            topology,
            canonical_component_bytes,
        )?;
        ordered_entries.push(SetupGeneratedGaloisEntry::from_browser_owned_witness(
            component,
            centered_error_polynomials_by_block,
        )?);
    }
    Ok(ordered_entries)
}

#[allow(clippy::too_many_arguments)]
fn construct_galois_component_bytes(
    selected_suite: &SelectedSuiteCapability,
    topology: &KeySwitchComponentMaterialTopology,
    schedule_position: u32,
    catalog_level: usize,
    common_secret_coefficients: &[i8],
    automorphed_secret_coefficients: &[i64],
    centered_error_polynomials_by_block: &[Zeroizing<Vec<i8>>],
    public_setup_seed: &[u8; Hash512::BYTE_LENGTH],
) -> Result<Vec<u8>, RefusalReason> {
    let active_data_modulus_count = catalog_level
        .checked_add(1)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let data_primes_per_block = usize::from(selected_suite.key_switch_data_primes_per_block());
    let expected_byte_length = usize::try_from(topology.expected_byte_length())
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    if topology.ordered_moduli().len()
        != active_data_modulus_count
            .checked_add(selected_suite.ordered_special_primes().len())
            .ok_or(RefusalReason::OutsideSupportedProfile)?
        || centered_error_polynomials_by_block.len() != topology.data_block_count()
        || common_secret_coefficients.len() != topology.polynomial_degree()
        || automorphed_secret_coefficients.len() != topology.polynomial_degree()
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }

    let mut canonical_bytes = Vec::with_capacity(expected_byte_length);
    for (decomposition_block_index, centered_error_polynomial) in
        centered_error_polynomials_by_block.iter().enumerate()
    {
        let block_start = decomposition_block_index
            .checked_mul(data_primes_per_block)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let block_end = block_start
            .checked_add(data_primes_per_block)
            .map(|end| end.min(active_data_modulus_count))
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        for (extended_limb_ordinal, modulus) in
            topology.ordered_moduli().iter().copied().enumerate()
        {
            let (modulus_catalog_identifier, modulus_index) =
                if extended_limb_ordinal < active_data_modulus_count {
                    (
                        DATA_MODULUS_CATALOG_IDENTIFIER,
                        u16::try_from(extended_limb_ordinal)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                    )
                } else {
                    (
                        SPECIAL_MODULUS_CATALOG_IDENTIFIER,
                        u16::try_from(extended_limb_ordinal - active_data_modulus_count)
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                    )
                };
            let public_common_reference = sample_galois_common_reference_limb(
                public_setup_seed,
                schedule_position,
                u16::try_from(decomposition_block_index)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                modulus_catalog_identifier,
                modulus_index,
                topology.polynomial_degree(),
            )
            .map_err(|_| RefusalReason::InvalidArithmeticRelation)?;
            let secret_residues = Zeroizing::new(
                common_secret_coefficients
                    .iter()
                    .copied()
                    .map(|coefficient| centered_i8_residue(coefficient, modulus))
                    .collect::<Vec<_>>(),
            );
            let common_reference_secret_product = Zeroizing::new(
                negacyclic_product_mod(&public_common_reference, &secret_residues, modulus)
                    .map_err(|_| RefusalReason::InvalidArithmeticRelation)?,
            );
            let gadget_residue = (extended_limb_ordinal >= block_start
                && extended_limb_ordinal < block_end)
                .then(|| special_basis_modulus_residue(modulus));
            let residue_byte_length = canonical_residue_byte_length(modulus)
                .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
            for coefficient_ordinal in 0..topology.polynomial_degree() {
                let error_residue = centered_i32_residue(
                    i32::from(centered_error_polynomial[coefficient_ordinal]),
                    modulus,
                );
                let scaled_error =
                    mul_mod_fast(PLAINTEXT_MODULUS % modulus, error_residue, modulus);
                let mut component_coefficient = sub_mod_fast(
                    scaled_error,
                    common_reference_secret_product[coefficient_ordinal],
                    modulus,
                );
                if let Some(gadget_residue) = gadget_residue {
                    let automorphed_secret_residue = centered_i64_residue(
                        automorphed_secret_coefficients[coefficient_ordinal],
                        modulus,
                    );
                    component_coefficient = add_mod_fast(
                        component_coefficient,
                        mul_mod_fast(gadget_residue, automorphed_secret_residue, modulus),
                        modulus,
                    );
                }
                canonical_bytes
                    .extend_from_slice(&component_coefficient.to_le_bytes()[..residue_byte_length]);
            }
        }
    }
    if canonical_bytes.len() != expected_byte_length {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    Ok(canonical_bytes)
}

pub(super) fn sample_centered_ternary_polynomial(
    selected_suite: &SelectedSuiteCapability,
    action_private_randomness: &ActionPrivateRandomness,
    domain: PrivateRandomnessDomain,
    context_hash: Hash512,
    setup_attempt_identifier: PrivateRandomnessAttemptIdentifier,
    ring_degree: usize,
) -> Result<Zeroizing<Vec<i8>>, RefusalReason> {
    let mut stream = action_private_randomness
        .begin_stream(domain, context_hash, setup_attempt_identifier)
        .map_err(|error| error.refusal_reason)?;
    let mut coefficients = Zeroizing::new(Vec::with_capacity(ring_degree));
    for _ in 0..ring_degree {
        coefficients.push(
            stream
                .sample_centered_ternary(
                    selected_suite.maximum_private_sampler_candidate_draws_per_output(),
                )
                .map_err(|error| error.refusal_reason)?,
        );
    }
    Ok(coefficients)
}

pub(super) fn sample_centered_binomial_polynomial(
    action_private_randomness: &ActionPrivateRandomness,
    domain: PrivateRandomnessDomain,
    context_hash: Hash512,
    setup_attempt_identifier: PrivateRandomnessAttemptIdentifier,
    parameter: u16,
    ring_degree: usize,
) -> Result<Zeroizing<Vec<i8>>, RefusalReason> {
    let mut stream = action_private_randomness
        .begin_stream(domain, context_hash, setup_attempt_identifier)
        .map_err(|error| error.refusal_reason)?;
    let mut coefficients = Zeroizing::new(Vec::with_capacity(ring_degree));
    for _ in 0..ring_degree {
        coefficients.push(
            i8::try_from(
                stream
                    .sample_centered_binomial(parameter)
                    .map_err(|error| error.refusal_reason)?,
            )
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
        );
    }
    Ok(coefficients)
}

fn sample_uniform_polynomial(
    selected_suite: &SelectedSuiteCapability,
    action_private_randomness: &ActionPrivateRandomness,
    domain: PrivateRandomnessDomain,
    context_hash: Hash512,
    setup_attempt_identifier: PrivateRandomnessAttemptIdentifier,
    modulus: u64,
    ring_degree: usize,
) -> Result<Zeroizing<Vec<u64>>, RefusalReason> {
    let mut stream = action_private_randomness
        .begin_stream(domain, context_hash, setup_attempt_identifier)
        .map_err(|error| error.refusal_reason)?;
    let mut coefficients = Zeroizing::new(Vec::with_capacity(ring_degree));
    for _ in 0..ring_degree {
        coefficients.push(
            stream
                .sample_modulo(
                    modulus,
                    selected_suite.maximum_private_sampler_candidate_draws_per_output(),
                )
                .map_err(|error| error.refusal_reason)?,
        );
    }
    Ok(coefficients)
}

fn sample_material_seed(
    action_private_randomness: &ActionPrivateRandomness,
    purpose: u16,
    material_context_hash: [u8; Hash512::BYTE_LENGTH],
    setup_attempt_identifier: PrivateRandomnessAttemptIdentifier,
) -> Result<Zeroizing<[u8; MATERIAL_SEED_BYTE_LENGTH]>, RefusalReason> {
    let mut stream = action_private_randomness
        .begin_stream(
            PrivateRandomnessDomain::vss_expansion(purpose)
                .map_err(|error| error.refusal_reason)?,
            Hash512::from_bytes(material_context_hash),
            setup_attempt_identifier,
        )
        .map_err(|error| error.refusal_reason)?;
    let mut material_seed = Zeroizing::new([0_u8; MATERIAL_SEED_BYTE_LENGTH]);
    stream
        .fill_bytes(&mut *material_seed)
        .map_err(|error| error.refusal_reason)?;
    Ok(material_seed)
}

fn evaluate_recipient_share(
    sharing_coefficients: &[Zeroizing<Vec<u64>>],
    recipient_roster_position: usize,
    point_stride: u64,
    modulus: u64,
) -> Result<Zeroizing<Vec<u64>>, RefusalReason> {
    let ring_degree = sharing_coefficients
        .first()
        .map(|coefficient| coefficient.len())
        .filter(|ring_degree| *ring_degree > 0 && ring_degree.is_power_of_two())
        .ok_or(RefusalReason::WrongTypeOrLength)?;
    if modulus <= 1
        || point_stride == 0
        || sharing_coefficients.iter().any(|coefficient| {
            coefficient.len() != ring_degree || coefficient.iter().any(|value| *value >= modulus)
        })
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let twice_ring_degree = u64::try_from(ring_degree)
        .ok()
        .and_then(|degree| degree.checked_mul(2))
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let recipient = u64::try_from(recipient_roster_position)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let mut share = Zeroizing::new(vec![0_u64; ring_degree]);
    for (coefficient_index, coefficient) in sharing_coefficients.iter().enumerate() {
        let exponent = recipient
            .checked_mul(
                u64::try_from(coefficient_index)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
            )
            .and_then(|product| product.checked_mul(point_stride))
            .map(|exponent| exponent % twice_ring_degree)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        add_negacyclic_monomial_action(&mut share, coefficient, exponent, modulus)?;
    }
    Ok(share)
}

fn add_negacyclic_monomial_action(
    accumulated: &mut [u64],
    source: &[u64],
    exponent: u64,
    modulus: u64,
) -> Result<(), RefusalReason> {
    if accumulated.len() != source.len()
        || accumulated.is_empty()
        || modulus <= 1
        || accumulated.iter().any(|value| *value >= modulus)
        || source.iter().any(|value| *value >= modulus)
    {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    let ring_degree =
        u64::try_from(source.len()).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let twice_ring_degree = ring_degree
        .checked_mul(2)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let exponent = exponent % twice_ring_degree;
    for (source_ordinal, source_coefficient) in source.iter().copied().enumerate() {
        let mapped_exponent = u64::try_from(source_ordinal)
            .ok()
            .and_then(|source_ordinal| source_ordinal.checked_add(exponent))
            .map(|mapped_exponent| mapped_exponent % twice_ring_degree)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let target_ordinal = usize::try_from(mapped_exponent % ring_degree)
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let signed_coefficient = if mapped_exponent >= ring_degree && source_coefficient != 0 {
            modulus - source_coefficient
        } else {
            source_coefficient
        };
        accumulated[target_ordinal] =
            add_mod_fast(accumulated[target_ordinal], signed_coefficient, modulus);
    }
    Ok(())
}

fn setup_source_sampler_context_hash(
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
) -> Result<Hash512, RefusalReason> {
    canonical_context_hash(
        SETUP_SOURCE_SAMPLER_CONTEXT_SCHEMA_IDENTIFIER,
        vec![CanonicalItem::hash512(source_setup_intent_object_hash)],
        SETUP_SOURCE_SAMPLER_CONTEXT_HASH_DOMAIN,
    )
}

fn galois_error_context_hash(
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
    schedule_position: u32,
    decomposition_block_index: u16,
) -> Result<Hash512, RefusalReason> {
    canonical_context_hash(
        GALOIS_ERROR_CONTEXT_SCHEMA_IDENTIFIER,
        vec![
            CanonicalItem::hash512(source_setup_intent_object_hash),
            CanonicalItem::unsigned32(schedule_position),
            CanonicalItem::unsigned16(decomposition_block_index),
        ],
        GALOIS_ERROR_CONTEXT_HASH_DOMAIN,
    )
}

fn public_key_error_context_hash(
    source_setup_intent_object_hash: [u8; Hash512::BYTE_LENGTH],
) -> Result<Hash512, RefusalReason> {
    canonical_context_hash(
        PUBLIC_KEY_ERROR_CONTEXT_SCHEMA_IDENTIFIER,
        vec![CanonicalItem::hash512(source_setup_intent_object_hash)],
        PUBLIC_KEY_ERROR_CONTEXT_HASH_DOMAIN,
    )
}

fn canonical_context_hash(
    schema_identifier: u16,
    items: Vec<CanonicalItem>,
    domain: &str,
) -> Result<Hash512, RefusalReason> {
    let canonical_bytes = CanonicalTuple::new(schema_identifier, FOUNDATION_SCHEMA_VERSION, items)
        .encode()
        .map_err(|_| RefusalReason::MalformedEncoding)?;
    hash_foundation_tuple_512(
        domain,
        &[CanonicalItem::variable_bytes(canonical_bytes)
            .map_err(|_| RefusalReason::MalformedEncoding)?],
    )
    .map_err(|_| RefusalReason::MalformedEncoding)
}

pub(super) fn centered_i8_residue(coefficient: i8, modulus: u64) -> u64 {
    centered_i64_residue(i64::from(coefficient), modulus)
}

fn centered_i32_residue(coefficient: i32, modulus: u64) -> u64 {
    centered_i64_residue(i64::from(coefficient), modulus)
}

fn centered_i64_residue(coefficient: i64, modulus: u64) -> u64 {
    if coefficient >= 0 {
        coefficient as u64 % modulus
    } else {
        let magnitude = coefficient.unsigned_abs() % modulus;
        if magnitude == 0 {
            0
        } else {
            modulus - magnitude
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::parameters::DATA_PRIMES;

    fn naive_negacyclic_product(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
        assert_eq!(left.len(), right.len());
        let ring_degree = left.len();
        let mut product = vec![0_u64; ring_degree];
        for (left_index, left_coefficient) in left.iter().copied().enumerate() {
            for (right_index, right_coefficient) in right.iter().copied().enumerate() {
                let term = mul_mod_fast(left_coefficient, right_coefficient, modulus);
                let degree = left_index + right_index;
                let coefficient_index = degree % ring_degree;
                product[coefficient_index] = if degree < ring_degree {
                    add_mod_fast(product[coefficient_index], term, modulus)
                } else {
                    sub_mod_fast(product[coefficient_index], term, modulus)
                };
            }
        }
        product
    }

    #[test]
    fn public_key_share_uses_every_selected_data_modulus_and_eight_sharing_limbs() {
        let public_key_relation = selected_public_key_share_relation_plan_input()
            .expect("selected public-key relation derives");
        let expected_public_indices = (0..DATA_PRIMES.len())
            .map(|data_modulus_index| u16::try_from(data_modulus_index).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            public_key_relation.data_modulus_indices,
            expected_public_indices
        );
        assert_eq!(public_key_relation.data_modulus_indices.len(), 23);

        let committed_material_relation = selected_committed_material_relation_plan_input()
            .expect("selected committed-material relation derives");
        assert_eq!(
            committed_material_relation
                .sharing_data_modulus_indices
                .len(),
            8
        );
    }

    #[test]
    fn public_key_share_limb_satisfies_the_rlwe_equation_with_one_shared_error() {
        let modulus = DATA_PRIMES[0];
        let common_reference = [2_u64, 5, 9, 14, 20, 27, 35, 44];
        let common_secret = [1_i8, -1, 0, 1, 0, -1, 1, 0];
        let centered_error = [2_i8, -2, 1, 0, -1, 2, 0, -2];
        let public_key_share = construct_public_key_share_limb(
            &common_reference,
            &common_secret,
            &centered_error,
            modulus,
        )
        .expect("the selected modulus supports the small negacyclic test ring");
        let secret_residues = common_secret
            .iter()
            .copied()
            .map(|coefficient| centered_i8_residue(coefficient, modulus))
            .collect::<Vec<_>>();
        let independently_computed_product =
            naive_negacyclic_product(&common_reference, &secret_residues, modulus);

        for coefficient_index in 0..common_reference.len() {
            let recovered_error_term = add_mod_fast(
                public_key_share[coefficient_index],
                independently_computed_product[coefficient_index],
                modulus,
            );
            let expected_error_term = mul_mod_fast(
                PLAINTEXT_MODULUS % modulus,
                centered_i8_residue(centered_error[coefficient_index], modulus),
                modulus,
            );
            assert_eq!(recovered_error_term, expected_error_term);
        }
    }

    #[test]
    fn recipient_share_uses_spaced_negacyclic_monomial_points() {
        let coefficients = [
            Zeroizing::new(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            Zeroizing::new(vec![8, 7, 6, 5, 4, 3, 2, 1]),
            Zeroizing::new(vec![2, 0, 4, 0, 6, 0, 8, 0]),
            Zeroizing::new(vec![0, 3, 0, 5, 0, 7, 0, 9]),
        ];
        let modulus = 17;

        let unit_point =
            evaluate_recipient_share(&coefficients, 0, 1, modulus).expect("unit-point share");
        assert_eq!(unit_point.as_slice(), &[11, 12, 13, 14, 15, 16, 0, 1]);

        let wrapped_point =
            evaluate_recipient_share(&coefficients, 3, 2, modulus).expect("wrapped monomial share");
        let mut independently_accumulated = vec![0_u64; 8];
        for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
            add_negacyclic_monomial_action(
                &mut independently_accumulated,
                coefficient,
                u64::try_from(3 * coefficient_index * 2).expect("small exponent"),
                modulus,
            )
            .expect("valid monomial action");
        }
        assert_eq!(wrapped_point.as_slice(), independently_accumulated);
        assert_ne!(wrapped_point.as_slice(), unit_point.as_slice());
    }

    #[test]
    fn recipient_share_rejects_detached_shapes_and_noncanonical_residues() {
        let mismatched = [Zeroizing::new(vec![1, 2, 3, 4]), Zeroizing::new(vec![1, 2])];
        assert_eq!(
            evaluate_recipient_share(&mismatched, 1, 1, 17),
            Err(RefusalReason::WrongTypeOrLength)
        );
        let noncanonical = [Zeroizing::new(vec![0, 1, 16, 17])];
        assert_eq!(
            evaluate_recipient_share(&noncanonical, 1, 1, 17),
            Err(RefusalReason::WrongTypeOrLength)
        );
        let empty: [Zeroizing<Vec<u64>>; 0] = [];
        assert_eq!(
            evaluate_recipient_share(&empty, 0, 1, 17),
            Err(RefusalReason::WrongTypeOrLength)
        );
    }

    #[test]
    fn private_sampler_contexts_separate_every_owned_coordinate() {
        let source_hash = [0x41; Hash512::BYTE_LENGTH];
        let different_source_hash = [0x42; Hash512::BYTE_LENGTH];
        let source_context =
            setup_source_sampler_context_hash(source_hash).expect("source sampler context");
        assert_ne!(
            source_context,
            setup_source_sampler_context_hash(different_source_hash)
                .expect("different source sampler context")
        );

        let baseline = galois_error_context_hash(source_hash, 3, 1).expect("Galois error context");
        assert_ne!(
            baseline,
            galois_error_context_hash(different_source_hash, 3, 1)
                .expect("different source context")
        );
        assert_ne!(
            baseline,
            galois_error_context_hash(source_hash, 4, 1).expect("different schedule context")
        );
        assert_ne!(
            baseline,
            galois_error_context_hash(source_hash, 3, 2).expect("different block context")
        );
    }

    #[test]
    fn centered_residue_conversion_covers_negative_and_large_values() {
        assert_eq!(centered_i64_residue(-18, 17), 16);
        assert_eq!(centered_i64_residue(-17, 17), 0);
        assert_eq!(centered_i64_residue(-1, 17), 16);
        assert_eq!(centered_i64_residue(0, 17), 0);
        assert_eq!(centered_i64_residue(18, 17), 1);
    }
}
