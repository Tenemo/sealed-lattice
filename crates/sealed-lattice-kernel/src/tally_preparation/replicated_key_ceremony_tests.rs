use crate::{
    foundation::{
        FOUNDATION_PROFILE, Hash512, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    replicated_key_ceremony::{
        REPLICATED_KEY_COMPONENT_BYTE_LENGTH, ReplicatedKeyCommitmentManifest,
        ReplicatedKeyComponentCommitment, ReplicatedKeyComponentOpening,
        ReplicatedKeyDeliveryAcknowledgement, ReplicatedRandomSharingKeyCoordinate,
        ReplicatedRandomSharingKeyPurpose, combine_replicated_random_sharing_key,
        create_replicated_key_component, create_replicated_key_delivery_acknowledgement,
        derive_replicated_key_commitment_manifest,
        derive_replicated_key_delivery_acknowledgement_root,
        expected_replicated_key_component_slots, validate_replicated_key_delivery_recipient,
        verify_replicated_key_component,
    },
    replicated_random_sharing::{ReplicatedRandomSharingGeometry, ReplicatedRandomSharingSubset},
};

#[test]
fn completion_ceremony_inventory_roundtrips_every_artifact_class() {
    let context = completion_context(31);
    let geometry = ReplicatedRandomSharingGeometry::derive(context.participant_count()).unwrap();
    let coordinates = ReplicatedRandomSharingKeyCoordinate::all(context).unwrap();
    assert_eq!(coordinates.len(), 480);
    assert_eq!(
        coordinates
            .iter()
            .filter(|coordinate| matches!(
                coordinate.purpose(),
                ReplicatedRandomSharingKeyPurpose::RandomSharing
            ))
            .count(),
        120
    );
    assert_eq!(
        coordinates
            .iter()
            .filter(|coordinate| matches!(
                coordinate.purpose(),
                ReplicatedRandomSharingKeyPurpose::DegreeDoubleZeroSharing { .. }
            ))
            .count(),
        360
    );

    let slots = expected_replicated_key_component_slots(context).unwrap();
    assert_eq!(slots.len(), 3_360);
    let mut commitments = Vec::with_capacity(slots.len());
    let mut first_opening_bytes = None;
    for (slot_position, (coordinate, contributor_position)) in slots.iter().copied().enumerate() {
        let (commitment, opening) = create_replicated_key_component(
            coordinate,
            contributor_position,
            component(slot_position, contributor_position),
        )
        .unwrap();
        if first_opening_bytes.is_none() {
            first_opening_bytes = Some(opening.canonical_bytes());
        }
        commitments.push(commitment);
    }

    let first_commitment_bytes = commitments[0].canonical_bytes();
    assert_eq!(
        ReplicatedKeyComponentCommitment::from_canonical_bytes(&first_commitment_bytes).unwrap(),
        commitments[0]
    );
    let first_opening_bytes = first_opening_bytes.unwrap();
    let first_opening =
        ReplicatedKeyComponentOpening::from_canonical_bytes(&first_opening_bytes).unwrap();
    verify_replicated_key_component(slots[0].0, slots[0].1, commitments[0], &first_opening)
        .unwrap();

    let manifest = derive_replicated_key_commitment_manifest(context, &commitments).unwrap();
    assert_eq!(manifest.commitment_count(), 3_360);
    assert_eq!(manifest.participant_count(), 10);
    assert_eq!(manifest.context_identity(), context.identity());
    assert_eq!(
        ReplicatedKeyCommitmentManifest::from_canonical_bytes(&manifest.canonical_bytes()).unwrap(),
        manifest
    );

    let acknowledgements = (0..context.participant_count())
        .map(|recipient_position| {
            create_replicated_key_delivery_acknowledgement(context, manifest, recipient_position)
                .unwrap()
        })
        .collect::<Vec<_>>();
    for (recipient_position, acknowledgement) in acknowledgements.iter().copied().enumerate() {
        assert_eq!(
            acknowledgement.recipient_position(),
            u16::try_from(recipient_position).unwrap()
        );
        assert_eq!(acknowledgement.expected_delivery_count(), 2_016);
        assert_eq!(
            ReplicatedKeyDeliveryAcknowledgement::from_canonical_bytes(
                &acknowledgement.canonical_bytes()
            )
            .unwrap(),
            acknowledgement
        );
    }
    let acknowledgement_root =
        derive_replicated_key_delivery_acknowledgement_root(context, manifest, &acknowledgements)
            .unwrap();
    assert_ne!(acknowledgement_root, manifest.root());
    assert_eq!(
        geometry.remote_key_component_delivery_count,
        acknowledgements
            .iter()
            .map(|acknowledgement| acknowledgement.expected_delivery_count())
            .sum::<u64>()
    );
}

#[test]
fn every_admitted_roster_derives_the_complete_canonical_slot_inventory() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let context = context_for_roster(participant_count, 43);
        let geometry = ReplicatedRandomSharingGeometry::derive(participant_count).unwrap();
        let coordinates = ReplicatedRandomSharingKeyCoordinate::all(context).unwrap();
        let slots = expected_replicated_key_component_slots(context).unwrap();

        assert_eq!(
            coordinates.len(),
            usize::try_from(geometry.total_key_count).unwrap()
        );
        assert_eq!(
            slots.len(),
            usize::try_from(geometry.total_key_count * geometry.authorized_subset_size).unwrap()
        );
        for coordinate in coordinates {
            assert_eq!(coordinate.context_identity(), context.identity());
            assert_eq!(coordinate.participant_count(), participant_count);
            assert_eq!(
                coordinate.member_positions().unwrap().len(),
                usize::try_from(geometry.authorized_subset_size).unwrap()
            );
            assert_eq!(
                ReplicatedRandomSharingKeyCoordinate::from_canonical_bytes(
                    &coordinate.canonical_bytes()
                )
                .unwrap(),
                coordinate
            );
        }
    }
}

#[test]
fn component_verification_binds_context_coordinate_contributor_and_component() {
    let context = completion_context(59);
    let alternate_context = completion_context(61);
    let coordinate = ReplicatedRandomSharingKeyCoordinate::all(context).unwrap()[0];
    let alternate_coordinate = ReplicatedRandomSharingKeyCoordinate::all(alternate_context)
        .unwrap()
        .into_iter()
        .find(|candidate| {
            candidate.excluded_position_mask() == coordinate.excluded_position_mask()
                && candidate.purpose() == coordinate.purpose()
        })
        .unwrap();
    let contributor_position = coordinate.member_positions().unwrap()[0];
    let next_contributor_position = coordinate.member_positions().unwrap()[1];
    let (commitment, opening) = create_replicated_key_component(
        coordinate,
        contributor_position,
        component(7, contributor_position),
    )
    .unwrap();

    verify_replicated_key_component(coordinate, contributor_position, commitment, &opening)
        .unwrap();
    assert!(matches!(
        verify_replicated_key_component(
            alternate_coordinate,
            contributor_position,
            commitment,
            &opening,
        ),
        Err(TallyPreparationError::ReplicatedKeyCoordinateMismatch)
    ));
    assert!(matches!(
        verify_replicated_key_component(
            coordinate,
            next_contributor_position,
            commitment,
            &opening,
        ),
        Err(TallyPreparationError::ReplicatedKeyCoordinateMismatch)
    ));

    let mut changed_opening_bytes = opening.canonical_bytes();
    *changed_opening_bytes.last_mut().unwrap() ^= 0x80;
    let changed_opening =
        ReplicatedKeyComponentOpening::from_canonical_bytes(&changed_opening_bytes).unwrap();
    assert!(matches!(
        verify_replicated_key_component(
            coordinate,
            contributor_position,
            commitment,
            &changed_opening,
        ),
        Err(TallyPreparationError::ReplicatedKeyCommitmentMismatch)
    ));

    let excluded_position = coordinate
        .excluded_position_mask()
        .trailing_zeros()
        .try_into()
        .unwrap();
    assert!(matches!(
        validate_replicated_key_delivery_recipient(
            coordinate,
            contributor_position,
            contributor_position,
        ),
        Err(TallyPreparationError::ReplicatedKeySelfDelivery)
    ));
    assert!(matches!(
        validate_replicated_key_delivery_recipient(
            coordinate,
            contributor_position,
            excluded_position,
        ),
        Err(TallyPreparationError::ReplicatedKeyRecipientNotMember { .. })
    ));
}

#[test]
fn every_coordinate_combines_exactly_one_component_from_each_member() {
    let context = completion_context(71);
    for (coordinate_position, coordinate) in ReplicatedRandomSharingKeyCoordinate::all(context)
        .unwrap()
        .into_iter()
        .enumerate()
    {
        let contributors = coordinate.member_positions().unwrap();
        let mut commitments = Vec::with_capacity(contributors.len());
        let mut openings = Vec::with_capacity(contributors.len());
        let mut expected_key = [0_u8; REPLICATED_KEY_COMPONENT_BYTE_LENGTH];
        for contributor_position in contributors {
            let component = component(coordinate_position, contributor_position);
            for (expected_byte, component_byte) in expected_key.iter_mut().zip(component) {
                *expected_byte ^= component_byte;
            }
            let (commitment, opening) =
                create_replicated_key_component(coordinate, contributor_position, component)
                    .unwrap();
            commitments.push(commitment);
            openings.push(opening);
        }

        let key =
            combine_replicated_random_sharing_key(coordinate, &commitments, &openings).unwrap();
        assert_eq!(key.as_bytes(), &expected_key);

        commitments.swap(0, 1);
        assert!(matches!(
            combine_replicated_random_sharing_key(coordinate, &commitments, &openings),
            Err(TallyPreparationError::ReplicatedKeyCoordinateMismatch)
        ));
    }
}

#[test]
fn manifests_and_acknowledgements_reject_missing_reordered_forked_and_trailing_records() {
    let context = completion_context(83);
    let slots = expected_replicated_key_component_slots(context).unwrap();
    let commitments = slots
        .iter()
        .copied()
        .enumerate()
        .map(|(slot_position, (coordinate, contributor_position))| {
            create_replicated_key_component(
                coordinate,
                contributor_position,
                component(slot_position, contributor_position),
            )
            .unwrap()
            .0
        })
        .collect::<Vec<_>>();
    let manifest = derive_replicated_key_commitment_manifest(context, &commitments).unwrap();

    assert!(matches!(
        derive_replicated_key_commitment_manifest(context, &commitments[..commitments.len() - 1]),
        Err(TallyPreparationError::ReplicatedKeyInventoryMismatch)
    ));
    let mut reordered_commitments = commitments.clone();
    reordered_commitments.swap(0, 1);
    assert!(matches!(
        derive_replicated_key_commitment_manifest(context, &reordered_commitments),
        Err(TallyPreparationError::ReplicatedKeyInventoryMismatch)
    ));

    let mut manifest_bytes = manifest.canonical_bytes();
    manifest_bytes.push(0);
    assert!(matches!(
        ReplicatedKeyCommitmentManifest::from_canonical_bytes(&manifest_bytes),
        Err(TallyPreparationError::TrailingReplicatedKeyArtifactBytes { .. })
    ));

    let mut acknowledgements = (0..context.participant_count())
        .map(|recipient_position| {
            create_replicated_key_delivery_acknowledgement(context, manifest, recipient_position)
                .unwrap()
        })
        .collect::<Vec<_>>();
    derive_replicated_key_delivery_acknowledgement_root(context, manifest, &acknowledgements)
        .unwrap();
    acknowledgements.swap(0, 1);
    assert!(matches!(
        derive_replicated_key_delivery_acknowledgement_root(context, manifest, &acknowledgements,),
        Err(TallyPreparationError::ReplicatedKeyAcknowledgementMismatch)
    ));

    let other_context = completion_context(89);
    assert!(matches!(
        create_replicated_key_delivery_acknowledgement(other_context, manifest, 0),
        Err(TallyPreparationError::ReplicatedKeyAcknowledgementMismatch)
    ));
}

#[test]
fn malformed_coordinate_magic_and_zero_basis_are_rejected() {
    let context = completion_context(97);
    let coordinate = ReplicatedRandomSharingKeyCoordinate::all(context).unwrap()[0];
    let mut bytes = coordinate.canonical_bytes();
    bytes[1] ^= 1;
    assert!(matches!(
        ReplicatedRandomSharingKeyCoordinate::from_canonical_bytes(&bytes),
        Err(TallyPreparationError::ReplicatedKeyArtifactMagicMismatch { .. })
    ));

    let subset = ReplicatedRandomSharingSubset::all(context.participant_count()).unwrap()[0];
    assert!(matches!(
        ReplicatedRandomSharingKeyCoordinate::new(
            context,
            subset,
            ReplicatedRandomSharingKeyPurpose::DegreeDoubleZeroSharing {
                basis_position: subset.active_fault_bound(),
            },
        ),
        Err(TallyPreparationError::ReplicatedKeyPurposeOutOfRange)
    ));
}

fn completion_context(attempt_byte: u8) -> TallyPreparationContext {
    context_for_roster(FOUNDATION_PROFILE.participant_count, attempt_byte)
}

fn context_for_roster(participant_count: u16, attempt_byte: u8) -> TallyPreparationContext {
    let option_count = FOUNDATION_PROFILE.option_count;
    let circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(participant_count, option_count, option_count).unwrap(),
    )
    .unwrap();
    TallyPreparationContext::new(
        Hash512::from_bytes([17_u8; 64]),
        Hash512::from_bytes([29_u8; 64]),
        [attempt_byte; 32],
        &circuit,
    )
    .unwrap()
}

fn component(
    coordinate_position: usize,
    contributor_position: u16,
) -> [u8; REPLICATED_KEY_COMPONENT_BYTE_LENGTH] {
    core::array::from_fn(|byte_position| {
        (coordinate_position as u8)
            .wrapping_mul(41)
            .wrapping_add((contributor_position as u8).wrapping_mul(17))
            .wrapping_add((byte_position as u8).wrapping_mul(29))
    })
}
