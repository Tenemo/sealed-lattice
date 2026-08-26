use crate::{
    foundation::{
        FOUNDATION_PROFILE, Hash512, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    pseudorandom_zero_sharing_seed_catalog_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INCLUSION_PROOF_DOMAIN,
        PseudorandomZeroSharingSeedCatalogLayout320,
    },
    pseudorandom_zero_sharing_seed_delivery_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_IDENTITY_DOMAIN,
        PseudorandomZeroSharingSeedDeliveryError320, PseudorandomZeroSharingSeedDeliveryLayout320,
    },
};

#[test]
fn every_ordered_pair_has_the_formula_derived_subset_and_payload_inventory() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let context = context(participant_count, participant_count as u8);
        let active_fault_bound = derive_foundation_roster_parameters(participant_count)
            .unwrap()
            .active_fault_bound;
        let expected_subset_count = choose(
            u64::from(participant_count - 2),
            u64::from(active_fault_bound),
        ) as usize;
        for sender_position in 0..participant_count {
            let catalog_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
                deterministic_hash(0x21, u64::from(participant_count)),
                context,
                sender_position,
            )
            .unwrap();
            let expected_proof_byte_length =
                independent_proof_byte_length(usize::from(catalog_layout.tree_height()));
            for recipient_position in 0..participant_count {
                if recipient_position == sender_position {
                    continue;
                }
                let delivery_layout = PseudorandomZeroSharingSeedDeliveryLayout320::derive(
                    catalog_layout,
                    recipient_position,
                )
                .unwrap();
                assert_eq!(delivery_layout.sender_catalog_layout(), catalog_layout);
                assert_eq!(delivery_layout.recipient_position(), recipient_position);
                assert_eq!(delivery_layout.subsets().len(), expected_subset_count);
                assert_eq!(
                    delivery_layout.leaf_count().unwrap(),
                    expected_subset_count + 1
                );
                assert_eq!(
                    delivery_layout.inclusion_proof_byte_length(),
                    expected_proof_byte_length
                );
                assert_eq!(
                    delivery_layout.payload_byte_length(),
                    expected_subset_count * (440 + expected_proof_byte_length)
                        + 444
                        + expected_proof_byte_length
                );
                assert!(
                    440 + expected_proof_byte_length < FOUNDATION_PROFILE.stream_chunk_byte_length
                );
                assert!(
                    444 + expected_proof_byte_length < FOUNDATION_PROFILE.stream_chunk_byte_length
                );
                let mut previous_mask = None;
                for subset in delivery_layout.subsets() {
                    assert!(subset.contains(sender_position).unwrap());
                    assert!(subset.contains(recipient_position).unwrap());
                    if let Some(previous_mask) = previous_mask {
                        assert!(previous_mask < subset.excluded_position_mask());
                    }
                    previous_mask = Some(subset.excluded_position_mask());
                }
            }
        }
    }
}

#[test]
fn completion_delivery_uses_fifty_seven_proofs_and_one_transport_chunk() {
    let catalog_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        deterministic_hash(0x41, 0),
        context(FOUNDATION_PROFILE.participant_count, 0x43),
        2,
    )
    .unwrap();
    let delivery_layout =
        PseudorandomZeroSharingSeedDeliveryLayout320::derive(catalog_layout, 7).unwrap();

    assert_eq!(delivery_layout.subsets().len(), 56);
    assert_eq!(delivery_layout.leaf_count().unwrap(), 57);
    assert_eq!(delivery_layout.inclusion_proof_byte_length(), 658);
    assert_eq!(delivery_layout.payload_byte_length(), 62_590);
    assert_eq!(
        u64::from(FOUNDATION_PROFILE.participant_count)
            * u64::from(FOUNDATION_PROFILE.participant_count - 1)
            * u64::try_from(delivery_layout.payload_byte_length()).unwrap(),
        5_633_100
    );
}

#[test]
fn delivery_layout_refuses_self_and_out_of_roster_endpoints() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let catalog_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        deterministic_hash(0x61, 0),
        context(participant_count, 0x63),
        4,
    )
    .unwrap();

    for recipient_position in [4, participant_count, u16::MAX] {
        assert_eq!(
            PseudorandomZeroSharingSeedDeliveryLayout320::derive(
                catalog_layout,
                recipient_position
            ),
            Err(
                PseudorandomZeroSharingSeedDeliveryError320::EndpointMismatch {
                    sender_position: 4,
                    recipient_position,
                    participant_count,
                }
            )
        );
    }
}

#[test]
fn delivery_and_recipient_domains_are_exact_and_distinct() {
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_DOMAIN,
        "sealed-lattice/v1/preparation/seed-delivery-descriptor"
    );
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_IDENTITY_DOMAIN,
        "sealed-lattice/v1/preparation/seed-delivery-identity"
    );
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_DOMAIN,
        "sealed-lattice/v1/preparation/seed-recipient-inventory"
    );
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_IDENTITY_DOMAIN,
        "sealed-lattice/v1/preparation/seed-recipient-inventory-identity"
    );
    let domains = [
        PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_IDENTITY_DOMAIN,
    ];
    for (domain_index, domain) in domains.iter().enumerate() {
        for other_domain in &domains[domain_index + 1..] {
            assert_ne!(domain, other_domain);
        }
    }
}

fn independent_proof_byte_length(tree_height: usize) -> usize {
    8 + (4 + tree_height) * 6
        + 4
        + PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INCLUSION_PROOF_DOMAIN.len()
        + 64
        + 8
        + 2
        + tree_height * 64
}

fn choose(total: u64, selected: u64) -> u64 {
    let selected = selected.min(total - selected);
    (0..selected).fold(1_u64, |value, offset| {
        value * (total - offset) / (offset + 1)
    })
}

fn context(participant_count: u16, attempt_marker: u8) -> TallyPreparationContext {
    let circuit =
        CompiledTallyCircuit::compile(TallyCircuitProfile::new(participant_count, 2, 2).unwrap())
            .unwrap();
    TallyPreparationContext::new(
        deterministic_hash(0x81, u64::from(participant_count)),
        deterministic_hash(0x83, u64::from(participant_count)),
        [attempt_marker; 32],
        &circuit,
    )
    .unwrap()
}

fn deterministic_hash(marker: u8, ordinal: u64) -> Hash512 {
    let mut bytes = [marker; Hash512::BYTE_LENGTH];
    bytes[..8].copy_from_slice(&ordinal.to_le_bytes());
    Hash512::from_bytes(bytes)
}
