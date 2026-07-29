use std::{cell::RefCell, slice};

use crate::{
    bgv::parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    foundation::{
        CanonicalItem, FOUNDATION_PROFILE, Hash512, ParticipantIdentity, RefusalReason,
        VerifiedSetupComplaintResolutionReservationHandle, VerifiedStateReservation,
        commit_accepted_setup_state_reservations, consume_verified_setup_complaint_resolution,
        hash_foundation_tuple_512, with_reserved_verified_setup_complaint_resolution,
    },
};

use super::{
    authority::{
        VerifiedAcceptedSetupAuthorityBorrowedInput, VerifiedAcceptedSetupAuthorityHandle,
        VerifiedAcceptedSetupAuthorityInput, VerifiedAcceptedSetupParticipantReleaseMaterial,
        VerifiedAcceptedSetupParticipantTargetReleaseSource,
        preflight_verified_accepted_setup_authority_destination,
        verified_collective_public_key_stream_descriptor,
    },
    canonical_package::{
        CanonicalAcceptedSetupPackage, VerifiedSetupTerminalReservationSet,
        setup_terminal_package_authorization_hash,
    },
    verified_public_proof_catalog::VerifiedAcceptedSetupPublicProofCatalog,
    verified_public_randomness::VerifiedPublicRandomness,
    verified_terminals::VerifiedVssQualificationTerminals,
    vss_qualification::VerifiedAcceptedSetupVssQualification,
};

const SETUP_ACTION_RANDOMNESS_AUTHORIZATION_DOMAIN: &str =
    "sealed-lattice/setup/state/action-randomness/v1";

/// Exact verified sources consumed by one accepted-setup publication. No field
/// can be constructed from a caller's proof descriptor list: the catalog and
/// VSS qualification are opaque capabilities minted by their family verifiers.
pub(in crate::bgv) struct VerifiedAcceptedSetupFinalizationInput {
    pub(in crate::bgv) package: CanonicalAcceptedSetupPackage,
    pub(in crate::bgv) vss_qualification: VerifiedAcceptedSetupVssQualification,
    pub(in crate::bgv) public_proof_catalog: VerifiedAcceptedSetupPublicProofCatalog,
    pub(in crate::bgv) complaint_resolution_handle:
        VerifiedSetupComplaintResolutionReservationHandle,
}

struct VerifiedAcceptedSetupFinalizationPreflight {
    expected_terminal_package_authorization_hash: Hash512,
    expected_action_randomness_authorizations: Vec<Hash512>,
    ordered_participant_identities: Vec<ParticipantIdentity>,
    setup_package_hash: Hash512,
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    ordered_data_modulus_indices: Vec<u16>,
    ordered_data_moduli: Vec<u64>,
    collective_public_key_root: [u8; Hash512::BYTE_LENGTH],
    collective_public_key_full_object_digest: [u8; Hash512::BYTE_LENGTH],
    collective_public_key_b_polynomials: Vec<std::sync::Arc<[u64]>>,
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
}

/// Publishes one accepted setup and consumes its reset-safe state reservations
/// as one transaction. All joins and destination allocation are fallible only
/// in preflight; the state runtime invokes an infallible authority insertion
/// before removing any reservation.
#[allow(clippy::too_many_arguments)]
pub(in crate::bgv) fn finalize_verified_accepted_setup(
    state_session_handle: u32,
    state_session_capability: &[u8],
    ordered_commitment_reservation_handles: &[u32],
    terminal_package_reservation_handles: &[u32],
    input: &RefCell<Option<VerifiedAcceptedSetupFinalizationInput>>,
) -> Result<VerifiedAcceptedSetupAuthorityHandle, u32> {
    let preflight = preflight_verified_accepted_setup_finalization(input)?;

    commit_accepted_setup_state_reservations(
        state_session_handle,
        state_session_capability,
        ordered_commitment_reservation_handles,
        terminal_package_reservation_handles,
        preflight.expected_terminal_package_authorization_hash,
        move |state_verifier, commitment_reservations, terminal_reservations| {
            let state_roster_hash = state_verifier
                .roster_hash()
                .map_err(|_| refusal_status(RefusalReason::WrongContext))?;
            if state_roster_hash.into_bytes() != preflight.roster_hash
                || commitment_reservations.len()
                    != usize::from(FOUNDATION_PROFILE.participant_count)
                || commitment_reservations.iter().enumerate().any(
                    |(roster_position, reservation)| {
                        !reservation_matches_action_randomness(
                            reservation,
                            Hash512::from_bytes(preflight.suite_identifier),
                            Hash512::from_bytes(preflight.ceremony_context_hash),
                            Hash512::from_bytes(preflight.action_context_hash),
                            preflight.ordered_participant_identities[roster_position],
                            preflight.expected_action_randomness_authorizations[roster_position],
                        )
                    },
                )
            {
                return Err(refusal_status(RefusalReason::WrongContext));
            }
            let terminal_reservation_set =
                VerifiedSetupTerminalReservationSet::from_borrowed_reservations(
                    terminal_reservations,
                    Hash512::from_bytes(preflight.roster_hash),
                    preflight.setup_package_hash,
                )
                .map_err(|error| refusal_status(error.refusal_reason))?;
            if terminal_reservation_set.suite_identifier()
                != Hash512::from_bytes(preflight.suite_identifier)
                || terminal_reservation_set.ceremony_context_hash()
                    != Hash512::from_bytes(preflight.ceremony_context_hash)
                || terminal_reservation_set.action_context_hash()
                    != Hash512::from_bytes(preflight.action_context_hash)
                || terminal_reservation_set.roster_hash()
                    != Hash512::from_bytes(preflight.roster_hash)
                || terminal_reservation_set.setup_package_hash() != preflight.setup_package_hash
                || terminal_reservation_set
                    .ordered_subject_participant_identities()
                    .iter()
                    .any(|identity| !preflight.ordered_participant_identities.contains(identity))
            {
                return Err(refusal_status(RefusalReason::WrongContext));
            }

            let destination = {
                let borrowed_input = input.borrow();
                let borrowed_input = borrowed_input
                    .as_ref()
                    .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
                let vss_qualification = &borrowed_input.vss_qualification;
                let public_proof_catalog = &borrowed_input.public_proof_catalog;
                preflight_verified_accepted_setup_authority_destination(
                    VerifiedAcceptedSetupAuthorityBorrowedInput {
                        protocol_version: preflight.protocol_version,
                        suite_identifier: preflight.suite_identifier,
                        ceremony_context_hash: preflight.ceremony_context_hash,
                        action_context_hash: preflight.action_context_hash,
                        manifest_hash: preflight.manifest_hash,
                        roster_hash: preflight.roster_hash,
                        setup_proof_context_hash: preflight.setup_proof_context_hash,
                        ring_degree: POLYNOMIAL_DEGREE,
                        ordered_data_modulus_indices: &preflight.ordered_data_modulus_indices,
                        ordered_data_moduli: &preflight.ordered_data_moduli,
                        participant_release_materials: vss_qualification
                            .participant_release_materials(),
                        participant_target_release_sources: slice::from_ref(
                            vss_qualification.local_target_release_source(),
                        ),
                        collective_public_key_full_object_digest: preflight
                            .collective_public_key_full_object_digest,
                        collective_public_key_b_polynomials: &preflight
                            .collective_public_key_b_polynomials,
                        public_setup_seed: preflight.public_setup_seed,
                    },
                    public_proof_catalog.verified_evaluator_key_store(),
                )
                .map_err(|_| refusal_status(RefusalReason::WrongContext))?
            };

            let VerifiedAcceptedSetupFinalizationInput {
                package: _,
                vss_qualification,
                public_proof_catalog,
                complaint_resolution_handle,
            } = input
                .borrow_mut()
                .take()
                .expect("borrowed finalization preflight retained the exact sources");
            let (
                _public_randomness,
                _vss_qualification_terminals,
                participant_release_materials,
                local_target_release_source,
            ) = vss_qualification.into_finalization_parts();
            let (collective_public_key_terminal, verified_evaluator_key_store) =
                public_proof_catalog.into_authority_material();
            drop(collective_public_key_terminal);
            let authority_input = VerifiedAcceptedSetupAuthorityInput {
                protocol_version: preflight.protocol_version,
                suite_identifier: preflight.suite_identifier,
                ceremony_context_hash: preflight.ceremony_context_hash,
                action_context_hash: preflight.action_context_hash,
                manifest_hash: preflight.manifest_hash,
                roster_hash: preflight.roster_hash,
                setup_proof_context_hash: preflight.setup_proof_context_hash,
                exact_verified_setup_source_hash: preflight.setup_package_hash.into_bytes(),
                ring_degree: POLYNOMIAL_DEGREE,
                ordered_data_modulus_indices: preflight.ordered_data_modulus_indices,
                ordered_data_moduli: preflight.ordered_data_moduli,
                participant_release_materials,
                participant_target_release_sources: vec![local_target_release_source],
                collective_public_key_root: preflight.collective_public_key_root,
                collective_public_key_full_object_digest: preflight
                    .collective_public_key_full_object_digest,
                collective_public_key_b_polynomials: preflight.collective_public_key_b_polynomials,
                public_setup_seed: preflight.public_setup_seed,
            };
            Ok((
                destination.complete(authority_input, verified_evaluator_key_store),
                complaint_resolution_handle,
            ))
        },
        |(prepared_authority, complaint_resolution_handle)| {
            consume_verified_setup_complaint_resolution(&complaint_resolution_handle);
            prepared_authority.commit()
        },
    )
}

fn preflight_verified_accepted_setup_finalization(
    input: &RefCell<Option<VerifiedAcceptedSetupFinalizationInput>>,
) -> Result<VerifiedAcceptedSetupFinalizationPreflight, u32> {
    let input = input.borrow();
    let input = input
        .as_ref()
        .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
    let package = &input.package;
    let vss_qualification = &input.vss_qualification;
    let public_randomness = vss_qualification.verified_public_randomness();
    let public_proof_catalog = &input.public_proof_catalog;
    let participant_target_release_sources =
        slice::from_ref(vss_qualification.local_target_release_source());
    validate_package_and_verified_sources(
        package,
        public_randomness,
        vss_qualification.qualification_terminals(),
        public_proof_catalog,
        vss_qualification.participant_release_materials(),
        participant_target_release_sources,
    )?;

    let context = public_randomness.context();
    with_reserved_verified_setup_complaint_resolution(
        &input.complaint_resolution_handle,
        |resolution| {
            resolution.require_matches(
                context.suite_identifier(),
                context.manifest_hash(),
                context.ceremony_context_hash(),
                context.action_context_hash(),
                context.roster_hash(),
                package.private_share_acceptance_object_hashes(),
            )
        },
    )
    .map_err(|_| refusal_status(RefusalReason::ConsumedState))?
    .map_err(refusal_status)?;
    let setup_package_hash = package.setup_package_hash();
    let expected_terminal_package_authorization_hash = setup_terminal_package_authorization_hash(
        context.suite_identifier(),
        context.ceremony_context_hash(),
        context.action_context_hash(),
        context.roster_hash(),
        setup_package_hash,
    )
    .map_err(|error| refusal_status(error.refusal_reason))?;
    let expected_action_randomness_authorizations = public_randomness
        .ordered_participant_identities()
        .iter()
        .copied()
        .zip(
            public_randomness
                .ordered_action_randomness_commitments()
                .iter()
                .copied(),
        )
        .map(|(participant_identity, action_randomness_commitment)| {
            setup_action_randomness_authorization_hash(
                context.suite_identifier(),
                context.ceremony_context_hash(),
                context.action_context_hash(),
                context.roster_hash(),
                participant_identity,
                action_randomness_commitment,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let collective_public_key_terminal = public_proof_catalog.collective_public_key_terminal();
    let public_setup_seed = public_randomness.public_setup_seed().into_bytes();
    let collective_public_key_descriptor = verified_collective_public_key_stream_descriptor(
        collective_public_key_terminal,
        public_setup_seed,
    )
    .map_err(|_| refusal_status(RefusalReason::WrongHashOrRoot))?;
    if package.collective_public_key_descriptor() != &collective_public_key_descriptor {
        return Err(refusal_status(RefusalReason::WrongHashOrRoot));
    }
    let ordered_data_modulus_indices = (0..DATA_PRIMES.len())
        .map(|ordinal| {
            u16::try_from(ordinal)
                .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(VerifiedAcceptedSetupFinalizationPreflight {
        expected_terminal_package_authorization_hash,
        expected_action_randomness_authorizations,
        ordered_participant_identities: public_randomness.ordered_participant_identities().to_vec(),
        setup_package_hash,
        protocol_version: context.protocol_version(),
        suite_identifier: context.suite_identifier().into_bytes(),
        ceremony_context_hash: context.ceremony_context_hash().into_bytes(),
        action_context_hash: context.action_context_hash().into_bytes(),
        manifest_hash: context.manifest_hash().into_bytes(),
        roster_hash: context.roster_hash().into_bytes(),
        setup_proof_context_hash: public_randomness.setup_proof_context_hash().into_bytes(),
        ordered_data_modulus_indices,
        ordered_data_moduli: DATA_PRIMES.to_vec(),
        collective_public_key_root: collective_public_key_terminal.collective_public_key_root(),
        collective_public_key_full_object_digest: collective_public_key_terminal
            .collective_public_key_full_object_digest(),
        collective_public_key_b_polynomials: collective_public_key_terminal
            .collective_public_key_b_polynomials()
            .to_vec(),
        public_setup_seed,
    })
}

fn validate_package_and_verified_sources(
    package: &CanonicalAcceptedSetupPackage,
    public_randomness: &VerifiedPublicRandomness,
    vss_qualification: &VerifiedVssQualificationTerminals,
    public_proof_catalog: &VerifiedAcceptedSetupPublicProofCatalog,
    participant_release_materials: &[VerifiedAcceptedSetupParticipantReleaseMaterial],
    participant_target_release_sources: &[VerifiedAcceptedSetupParticipantTargetReleaseSource],
) -> Result<(), u32> {
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let context = public_randomness.context();
    require_exact_verified_object_hash_catalog(
        package.setup_intent_object_hashes(),
        public_randomness.ordered_setup_intent_object_hashes(),
        participant_count,
    )?;
    require_exact_verified_object_hash_catalog(
        package.public_randomness_commitment_object_hashes(),
        public_randomness.ordered_commitment_object_hashes(),
        participant_count,
    )?;
    require_exact_verified_object_hash_catalog(
        package.public_randomness_reveal_object_hashes(),
        public_randomness.ordered_reveal_object_hashes(),
        participant_count,
    )?;
    require_exact_verified_object_hash_catalog(
        package.dealer_public_record_object_hashes(),
        vss_qualification.ordered_dealer_public_record_object_hashes(),
        participant_count,
    )?;
    require_exact_verified_object_hash_catalog(
        package.private_share_acceptance_object_hashes(),
        vss_qualification.ordered_private_share_acceptance_object_hashes(),
        participant_count,
    )?;
    require_exact_verified_vss_proof_descriptor_catalog(
        vss_qualification.ordered_share_linkage_proof_descriptors(),
        vss_qualification.ordered_aggregate_threshold_share_proof_descriptors(),
        participant_count,
    )?;
    if public_randomness.ordered_participant_identities().len() != participant_count
        || public_randomness
            .ordered_action_randomness_commitments()
            .len()
            != participant_count
        || public_proof_catalog.protocol_version() != context.protocol_version()
        || public_proof_catalog.suite_identifier() != context.suite_identifier().into_bytes()
        || public_proof_catalog.manifest_hash() != context.manifest_hash().into_bytes()
        || public_proof_catalog.ceremony_context_hash()
            != context.ceremony_context_hash().into_bytes()
        || public_proof_catalog.action_context_hash() != context.action_context_hash().into_bytes()
        || public_proof_catalog.roster_hash() != context.roster_hash().into_bytes()
        || public_proof_catalog.setup_proof_context_hash()
            != public_randomness.setup_proof_context_hash().into_bytes()
        || package.ordered_proof_descriptors()
            != public_proof_catalog.ordered_proof_stream_descriptors()
        || package.evaluator_key_store_descriptor()
            != public_proof_catalog
                .verified_evaluator_key_store()
                .verified_evaluator_key_store_stream()
                .stream_descriptor()
        || participant_release_materials.len() != participant_count
        || participant_target_release_sources.len() != 1
    {
        return Err(refusal_status(RefusalReason::WrongContext));
    }

    for (roster_position, release_material) in participant_release_materials.iter().enumerate() {
        let expected_identity = public_randomness.ordered_participant_identities()[roster_position];
        if vss_qualification.ordered_participant_identities()[roster_position] != expected_identity
            || public_proof_catalog.ordered_participant_identities()[roster_position]
                != expected_identity.into_bytes()
            || vss_qualification.degree_zero_vss_material_roots_for_dealer(roster_position)
                != public_proof_catalog
                    .degree_zero_commitment_roots_for_participant(roster_position)
            || release_material.participant_identity() != expected_identity.into_bytes()
            || usize::from(release_material.roster_position()) != roster_position
            || Some(release_material.ordered_aggregate_threshold_roots())
                != vss_qualification
                    .aggregate_threshold_share_material_roots_for_recipient(roster_position)
        {
            return Err(refusal_status(RefusalReason::WrongHashOrRoot));
        }
    }
    let local_target_source = &participant_target_release_sources[0];
    if participant_release_materials
        .get(usize::from(local_target_source.roster_position()))
        .is_none_or(|release_material| {
            release_material.participant_identity() != local_target_source.participant_identity()
        })
    {
        return Err(refusal_status(RefusalReason::WrongContext));
    }
    Ok(())
}

fn require_exact_verified_object_hash_catalog(
    package_object_hashes: &[Hash512],
    verified_object_hashes: &[Hash512],
    participant_count: usize,
) -> Result<(), u32> {
    if package_object_hashes.len() != participant_count
        || verified_object_hashes.len() != participant_count
    {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    if package_object_hashes != verified_object_hashes {
        return Err(refusal_status(RefusalReason::WrongHashOrRoot));
    }
    Ok(())
}

fn require_exact_verified_vss_proof_descriptor_catalog(
    ordered_vss_share_linkage_proof_descriptors: &[crate::foundation::StreamDescriptor],
    ordered_aggregate_threshold_share_proof_descriptors: &[crate::foundation::StreamDescriptor],
    participant_count: usize,
) -> Result<(), u32> {
    if ordered_vss_share_linkage_proof_descriptors.len() != participant_count
        || ordered_aggregate_threshold_share_proof_descriptors.len() != participant_count
        || ordered_vss_share_linkage_proof_descriptors
            .iter()
            .chain(ordered_aggregate_threshold_share_proof_descriptors)
            .any(|descriptor| descriptor.total_byte_length == 0)
    {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let ordered_descriptors = ordered_vss_share_linkage_proof_descriptors
        .iter()
        .chain(ordered_aggregate_threshold_share_proof_descriptors)
        .collect::<Vec<_>>();
    if ordered_descriptors
        .iter()
        .enumerate()
        .any(|(ordinal, descriptor)| ordered_descriptors[..ordinal].contains(descriptor))
    {
        return Err(refusal_status(RefusalReason::WrongHashOrRoot));
    }
    Ok(())
}

fn setup_action_randomness_authorization_hash(
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster_hash: Hash512,
    participant_identity: ParticipantIdentity,
    action_randomness_commitment: Hash512,
) -> Result<Hash512, u32> {
    hash_foundation_tuple_512(
        SETUP_ACTION_RANDOMNESS_AUTHORIZATION_DOMAIN,
        &[
            CanonicalItem::hash512(suite_identifier.into_bytes()),
            CanonicalItem::hash512(ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(action_context_hash.into_bytes()),
            CanonicalItem::hash512(roster_hash.into_bytes()),
            CanonicalItem::participant_identity(participant_identity.into_bytes()),
            CanonicalItem::hash512(action_randomness_commitment.into_bytes()),
        ],
    )
    .map_err(|_| refusal_status(RefusalReason::MalformedEncoding))
}

fn reservation_matches_action_randomness(
    reservation: &VerifiedStateReservation,
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    participant_identity: ParticipantIdentity,
    authorization_hash: Hash512,
) -> bool {
    reservation.suite_id() == suite_identifier
        && reservation.ceremony_context_hash() == ceremony_context_hash
        && reservation.action_context_hash() == action_context_hash
        && reservation.subject_participant_id() == participant_identity
        && reservation.authorization_hash() == authorization_hash
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::StreamDescriptor;

    fn catalog_hash(marker: u8) -> Hash512 {
        Hash512::from_bytes([marker; Hash512::BYTE_LENGTH])
    }

    fn stream_descriptor(marker: u8) -> StreamDescriptor {
        StreamDescriptor::new(
            1,
            vec![catalog_hash(marker)],
            catalog_hash(marker.wrapping_add(1)),
        )
        .expect("one-byte test stream descriptor is valid")
    }

    #[test]
    fn exact_verified_object_hash_catalog_rejects_length_and_order_drift() {
        let verified_hashes = [catalog_hash(0x11), catalog_hash(0x22), catalog_hash(0x33)];
        assert_eq!(
            require_exact_verified_object_hash_catalog(&verified_hashes, &verified_hashes, 3),
            Ok(())
        );

        assert_eq!(
            require_exact_verified_object_hash_catalog(&verified_hashes[..2], &verified_hashes, 3,),
            Err(refusal_status(RefusalReason::WrongTypeOrLength))
        );

        let reordered_hashes = [verified_hashes[1], verified_hashes[0], verified_hashes[2]];
        assert_eq!(
            require_exact_verified_object_hash_catalog(&reordered_hashes, &verified_hashes, 3),
            Err(refusal_status(RefusalReason::WrongHashOrRoot))
        );
    }

    #[test]
    fn exact_verified_vss_descriptor_catalog_rejects_missing_zero_length_and_duplicate_sources() {
        let share_linkage_descriptors = [stream_descriptor(0x41), stream_descriptor(0x51)];
        let aggregate_share_descriptors = [stream_descriptor(0x61), stream_descriptor(0x71)];
        assert_eq!(
            require_exact_verified_vss_proof_descriptor_catalog(
                &share_linkage_descriptors,
                &aggregate_share_descriptors,
                2,
            ),
            Ok(())
        );

        assert_eq!(
            require_exact_verified_vss_proof_descriptor_catalog(
                &share_linkage_descriptors[..1],
                &aggregate_share_descriptors,
                2,
            ),
            Err(refusal_status(RefusalReason::WrongTypeOrLength))
        );

        let mut zero_length_descriptors = aggregate_share_descriptors.clone();
        zero_length_descriptors[0].total_byte_length = 0;
        assert_eq!(
            require_exact_verified_vss_proof_descriptor_catalog(
                &share_linkage_descriptors,
                &zero_length_descriptors,
                2,
            ),
            Err(refusal_status(RefusalReason::WrongTypeOrLength))
        );

        let duplicate_descriptors = [
            aggregate_share_descriptors[0].clone(),
            share_linkage_descriptors[0].clone(),
        ];
        assert_eq!(
            require_exact_verified_vss_proof_descriptor_catalog(
                &share_linkage_descriptors,
                &duplicate_descriptors,
                2,
            ),
            Err(refusal_status(RefusalReason::WrongHashOrRoot))
        );
    }
}
