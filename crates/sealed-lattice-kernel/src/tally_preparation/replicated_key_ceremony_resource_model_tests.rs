use crate::{
    foundation::{
        FOUNDATION_PROFILE, Hash512, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    replicated_key_ceremony::{
        REPLICATED_KEY_ARTIFACT_VERSION, REPLICATED_KEY_COMMITMENT_MANIFEST_MAGIC,
        REPLICATED_KEY_COMPONENT_BYTE_LENGTH, REPLICATED_KEY_COMPONENT_COMMITMENT_BYTE_LENGTH,
        REPLICATED_KEY_COMPONENT_COMMITMENT_MAGIC, REPLICATED_KEY_COMPONENT_OPENING_MAGIC,
        REPLICATED_KEY_DELIVERY_ACKNOWLEDGEMENT_MAGIC, expected_replicated_key_component_slots,
    },
    replicated_key_ceremony_resource_model::ReplicatedKeyCeremonyResourceModel,
    replicated_random_sharing::ReplicatedRandomSharingGeometry,
};

#[test]
fn completion_profile_reproduces_the_exact_ceremony_core_bytes() {
    let model = ReplicatedKeyCeremonyResourceModel::derive(completion_context()).unwrap();

    assert_eq!(
        model,
        ReplicatedKeyCeremonyResourceModel {
            participant_count: 10,
            active_fault_bound: 3,
            authorized_subset_size: 7,
            key_count: 480,
            key_count_per_participant: 336,
            component_commitment_count: 3_360,
            unique_component_opening_count: 3_360,
            private_component_delivery_count: 20_160,
            raw_component_byte_length: 215_040,
            raw_private_component_delivery_byte_length: 1_290_240,
            component_commitment_canonical_byte_length: 774_340,
            unique_component_opening_canonical_byte_length: 764_260,
            private_delivery_plaintext_byte_length: 4_585_560,
            commitment_manifest_canonical_byte_length: 184,
            delivery_acknowledgement_count: 10,
            delivery_acknowledgement_canonical_byte_length: 1_900,
            acknowledgement_root_byte_length: 64,
            public_core_byte_length: 776_488,
            maximum_public_commitment_upload_byte_length_per_participant: 77_452,
            maximum_private_delivery_plaintext_upload_byte_length_per_participant: 458_664,
            maximum_private_delivery_plaintext_download_byte_length_per_participant: 458_664,
            maximum_component_custody_byte_length_per_participant: 535_108,
            combined_key_persistent_byte_length_per_participant: 21_504,
        }
    );

    assert_eq!(
        model,
        independently_derive_resource_model(completion_context())
    );
}

#[test]
fn small_and_completion_profiles_match_the_independent_canonical_length_derivation() {
    for participant_count in [MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, 10] {
        let circuit = circuit_for_roster(participant_count);
        let production = ReplicatedKeyCeremonyResourceModel::derive_for_circuit(&circuit).unwrap();
        let context = TallyPreparationContext::new(
            Hash512::from_bytes([0_u8; 64]),
            Hash512::from_bytes([0_u8; 64]),
            [0_u8; 32],
            &circuit,
        )
        .unwrap();
        let independent = independently_derive_resource_model(context);

        assert_eq!(production, independent);
        assert!(
            production.private_delivery_plaintext_byte_length
                > production.raw_private_component_delivery_byte_length
        );
        assert!(
            production.maximum_component_custody_byte_length_per_participant
                > production.combined_key_persistent_byte_length_per_participant
        );
    }
}

#[test]
fn every_admitted_roster_has_bounded_formula_only_geometry() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let geometry = ReplicatedRandomSharingGeometry::derive(participant_count).unwrap();
        assert_eq!(
            geometry.all_member_contribution_count,
            geometry.total_key_count * geometry.authorized_subset_size
        );
        assert_eq!(
            geometry.remote_key_component_delivery_count,
            geometry.all_member_contribution_count * (geometry.authorized_subset_size - 1)
        );
    }
}

fn independently_derive_resource_model(
    context: TallyPreparationContext,
) -> ReplicatedKeyCeremonyResourceModel {
    let geometry = ReplicatedRandomSharingGeometry::derive(context.participant_count()).unwrap();
    let slots = expected_replicated_key_component_slots(context).unwrap();
    let participant_count = usize::from(context.participant_count());
    let mut public_uploads = vec![0_u64; participant_count];
    let mut private_uploads = vec![0_u64; participant_count];
    let mut private_downloads = vec![0_u64; participant_count];
    let mut own_opening_bytes = vec![0_u64; participant_count];
    let mut commitment_bytes = 0_u64;
    let mut unique_opening_bytes = 0_u64;
    let mut private_delivery_bytes = 0_u64;

    for (coordinate, contributor_position) in &slots {
        let coordinate_byte_length = coordinate.canonical_bytes().len();
        let commitment_byte_length = framed_bytes_length(REPLICATED_KEY_COMPONENT_COMMITMENT_MAGIC)
            + varuint_length(REPLICATED_KEY_ARTIFACT_VERSION)
            + framed_length(coordinate_byte_length)
            + varuint_length(u64::from(*contributor_position))
            + framed_length(REPLICATED_KEY_COMPONENT_COMMITMENT_BYTE_LENGTH);
        let opening_byte_length = framed_bytes_length(REPLICATED_KEY_COMPONENT_OPENING_MAGIC)
            + varuint_length(REPLICATED_KEY_ARTIFACT_VERSION)
            + framed_length(coordinate_byte_length)
            + varuint_length(u64::from(*contributor_position))
            + framed_length(REPLICATED_KEY_COMPONENT_BYTE_LENGTH);
        commitment_bytes += commitment_byte_length as u64;
        unique_opening_bytes += opening_byte_length as u64;
        public_uploads[usize::from(*contributor_position)] += commitment_byte_length as u64;
        own_opening_bytes[usize::from(*contributor_position)] += opening_byte_length as u64;
        for recipient_position in coordinate.member_positions().unwrap() {
            if recipient_position != *contributor_position {
                private_delivery_bytes += opening_byte_length as u64;
                private_uploads[usize::from(*contributor_position)] += opening_byte_length as u64;
                private_downloads[usize::from(recipient_position)] += opening_byte_length as u64;
            }
        }
    }

    let commitment_count = slots.len() as u64;
    let manifest_byte_length = framed_bytes_length(REPLICATED_KEY_COMMITMENT_MANIFEST_MAGIC)
        + varuint_length(REPLICATED_KEY_ARTIFACT_VERSION)
        + framed_length(Hash512::BYTE_LENGTH)
        + varuint_length(u64::from(context.participant_count()))
        + varuint_length(commitment_count)
        + framed_length(Hash512::BYTE_LENGTH);
    let expected_delivery_count =
        geometry.key_count_per_participant * (geometry.authorized_subset_size - 1);
    let acknowledgement_byte_length =
        framed_bytes_length(REPLICATED_KEY_DELIVERY_ACKNOWLEDGEMENT_MAGIC)
            + varuint_length(REPLICATED_KEY_ARTIFACT_VERSION)
            + framed_length(Hash512::BYTE_LENGTH)
            + varuint_length(u64::from(context.participant_count()))
            + varuint_length(0)
            + framed_length(Hash512::BYTE_LENGTH)
            + varuint_length(expected_delivery_count);
    // Every admitted roster position fits the same one-byte varuint range.
    assert!(context.participant_count() < 128);
    let total_acknowledgement_bytes =
        acknowledgement_byte_length as u64 * u64::from(context.participant_count());

    ReplicatedKeyCeremonyResourceModel {
        participant_count: geometry.participant_count,
        active_fault_bound: geometry.active_fault_bound,
        authorized_subset_size: geometry.authorized_subset_size,
        key_count: geometry.total_key_count,
        key_count_per_participant: geometry.key_count_per_participant,
        component_commitment_count: commitment_count,
        unique_component_opening_count: commitment_count,
        private_component_delivery_count: geometry.remote_key_component_delivery_count,
        raw_component_byte_length: commitment_count * REPLICATED_KEY_COMPONENT_BYTE_LENGTH as u64,
        raw_private_component_delivery_byte_length: geometry.remote_key_component_byte_length,
        component_commitment_canonical_byte_length: commitment_bytes,
        unique_component_opening_canonical_byte_length: unique_opening_bytes,
        private_delivery_plaintext_byte_length: private_delivery_bytes,
        commitment_manifest_canonical_byte_length: manifest_byte_length as u64,
        delivery_acknowledgement_count: u64::from(context.participant_count()),
        delivery_acknowledgement_canonical_byte_length: total_acknowledgement_bytes,
        acknowledgement_root_byte_length: Hash512::BYTE_LENGTH as u64,
        public_core_byte_length: commitment_bytes
            + manifest_byte_length as u64
            + total_acknowledgement_bytes
            + Hash512::BYTE_LENGTH as u64,
        maximum_public_commitment_upload_byte_length_per_participant: *public_uploads
            .iter()
            .max()
            .unwrap(),
        maximum_private_delivery_plaintext_upload_byte_length_per_participant: *private_uploads
            .iter()
            .max()
            .unwrap(),
        maximum_private_delivery_plaintext_download_byte_length_per_participant: *private_downloads
            .iter()
            .max()
            .unwrap(),
        maximum_component_custody_byte_length_per_participant: own_opening_bytes
            .iter()
            .zip(&private_downloads)
            .map(|(own_bytes, remote_bytes)| own_bytes + remote_bytes)
            .max()
            .unwrap(),
        combined_key_persistent_byte_length_per_participant: geometry.key_count_per_participant
            * geometry.key_byte_length,
    }
}

fn framed_bytes_length(bytes: &[u8]) -> usize {
    framed_length(bytes.len())
}

fn framed_length(byte_length: usize) -> usize {
    varuint_length(byte_length as u64) + byte_length
}

fn varuint_length(mut value: u64) -> usize {
    let mut byte_length = 1;
    while value >= 128 {
        value >>= 7;
        byte_length += 1;
    }
    byte_length
}

fn completion_context() -> TallyPreparationContext {
    let circuit = circuit_for_roster(FOUNDATION_PROFILE.participant_count);
    TallyPreparationContext::new(
        Hash512::from_bytes([17_u8; 64]),
        Hash512::from_bytes([29_u8; 64]),
        [31_u8; 32],
        &circuit,
    )
    .unwrap()
}

fn circuit_for_roster(participant_count: u16) -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap()
}
