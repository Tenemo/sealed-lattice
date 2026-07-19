use crate::{
    bgv::proof_suite::{VerifiedEvaluatorKeyStore, VerifiedRelinearizationAggregateMaterial},
    foundation::{
        FOUNDATION_PROFILE, Hash512, ProofApplicationSlotCeilings, RefusalReason, StreamDescriptor,
        selected_sharing_data_prime_coordinates,
    },
};

use super::{
    canonical_package::{
        SelectedAcceptedSetupPublicProofSlot, selected_accepted_setup_public_proof_slots,
    },
    evaluator_source::VerifiedAcceptedSetupEvaluatorSourceCatalog,
    verified_terminals::{
        VerifiedCollectivePublicKeyTerminal, VerifiedPublicKeyShareTerminal,
        VerifiedSameSecretTerminal,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ObservedVerifiedAcceptedSetupPublicProofSlot {
    application_statement_schema_identifier: u16,
    roster_position: Option<u16>,
    schedule_position: Option<u32>,
}

impl ObservedVerifiedAcceptedSetupPublicProofSlot {
    const fn new(
        application_statement_schema_identifier: u16,
        roster_position: Option<u16>,
        schedule_position: Option<u32>,
    ) -> Self {
        Self {
            application_statement_schema_identifier,
            roster_position,
            schedule_position,
        }
    }
}

/// Verifier-owned catalog of the exact selected setup proof inventory.
/// Construction consumes every family terminal, joins their common witnesses,
/// and derives canonical proof order without consulting a package descriptor.
pub(in crate::bgv) struct VerifiedAcceptedSetupPublicProofCatalog {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    ordered_participant_identities: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_degree_zero_commitment_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_proof_stream_descriptors: Box<[StreamDescriptor]>,
    collective_public_key_terminal: VerifiedCollectivePublicKeyTerminal,
    verified_evaluator_key_store: VerifiedEvaluatorKeyStore,
}

/// Borrowed, allocation-complete proof inventory validation. Opaque family
/// terminals remain in their assembly slots until this record proves every
/// common-witness join and the complete canonical proof order.
pub(super) struct VerifiedAcceptedSetupPublicProofCatalogPreflight {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    ordered_participant_identities: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_degree_zero_commitment_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    ordered_proof_stream_descriptors: Box<[StreamDescriptor]>,
}

impl VerifiedAcceptedSetupPublicProofCatalogPreflight {
    pub(super) fn ordered_proof_stream_descriptors(&self) -> &[StreamDescriptor] {
        &self.ordered_proof_stream_descriptors
    }
}

impl VerifiedAcceptedSetupPublicProofCatalog {
    pub(super) fn preflight_from_verified_family_terminals(
        ordered_same_secret_terminals: &[&VerifiedSameSecretTerminal],
        ordered_public_key_share_terminals: &[&VerifiedPublicKeyShareTerminal],
        collective_public_key_terminal: &VerifiedCollectivePublicKeyTerminal,
        relinearization_aggregate: &VerifiedRelinearizationAggregateMaterial,
        evaluator_source_catalog: &VerifiedAcceptedSetupEvaluatorSourceCatalog,
        verified_evaluator_key_store: &VerifiedEvaluatorKeyStore,
    ) -> Result<VerifiedAcceptedSetupPublicProofCatalogPreflight, RefusalReason> {
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        if ordered_same_secret_terminals.len() != participant_count
            || ordered_public_key_share_terminals.len() != participant_count
            || relinearization_aggregate
                .ordered_participant_identities()
                .len()
                != participant_count
            || relinearization_aggregate
                .ordered_anchor_commitment_roots()
                .len()
                != participant_count
            || relinearization_aggregate
                .ordered_round_one_proof_stream_descriptors()
                .len()
                != participant_count
            || evaluator_source_catalog.ordered_participants().len() != participant_count
            || collective_public_key_terminal
                .ordered_public_key_share_roots()
                .len()
                != participant_count
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        let first_same_secret = ordered_same_secret_terminals
            .first()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let protocol_version = first_same_secret.protocol_version();
        let suite_identifier = first_same_secret.suite_identifier();
        let manifest_hash = first_same_secret.manifest_hash();
        let ceremony_context_hash = first_same_secret.ceremony_context_hash();
        let action_context_hash = first_same_secret.action_context_hash();
        let roster_hash = first_same_secret.roster_hash();
        let setup_proof_context_hash = first_same_secret.setup_proof_context_hash();
        let selected_public_proof_slots =
            selected_accepted_setup_public_proof_slots().map_err(|error| error.refusal_reason)?;
        let selected_relinearization_schedule_positions = selected_public_proof_slots
            .iter()
            .filter_map(|slot| {
                (slot.application_statement_schema_identifier()
                    == ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER)
                    .then_some(slot.schedule_position())
            })
            .collect::<Vec<_>>();
        if protocol_version != FOUNDATION_PROFILE.protocol_version
            || selected_relinearization_schedule_positions.len() != 1
            || !selected_relinearization_schedule_positions
                .contains(&Some(relinearization_aggregate.schedule_position()))
            || collective_public_key_terminal.protocol_version() != protocol_version
            || collective_public_key_terminal.suite_identifier() != suite_identifier
            || collective_public_key_terminal.ceremony_context_hash() != ceremony_context_hash
            || collective_public_key_terminal.action_context_hash() != action_context_hash
            || collective_public_key_terminal.roster_hash() != roster_hash
            || collective_public_key_terminal.setup_proof_context_hash() != setup_proof_context_hash
            || relinearization_aggregate.protocol_version() != protocol_version
            || relinearization_aggregate.suite_identifier() != suite_identifier
            || relinearization_aggregate.ceremony_context_hash() != ceremony_context_hash
            || relinearization_aggregate.action_context_hash() != action_context_hash
            || relinearization_aggregate.roster_hash() != roster_hash
            || relinearization_aggregate.setup_proof_context_hash() != setup_proof_context_hash
            || evaluator_source_catalog.protocol_version() != protocol_version
            || evaluator_source_catalog.suite_identifier() != suite_identifier
            || evaluator_source_catalog.manifest_hash() != manifest_hash
            || evaluator_source_catalog.ceremony_context_hash() != ceremony_context_hash
            || evaluator_source_catalog.action_context_hash() != action_context_hash
            || evaluator_source_catalog.roster_hash() != roster_hash
            || evaluator_source_catalog.setup_proof_context_hash() != setup_proof_context_hash
            || verified_evaluator_key_store.protocol_version() != protocol_version
            || verified_evaluator_key_store.suite_identifier() != suite_identifier
            || verified_evaluator_key_store.manifest_hash() != manifest_hash
            || verified_evaluator_key_store.ceremony_context_hash() != ceremony_context_hash
            || verified_evaluator_key_store.action_context_hash() != action_context_hash
            || verified_evaluator_key_store.roster_hash() != roster_hash
            || verified_evaluator_key_store.setup_proof_context_hash() != setup_proof_context_hash
            || verified_evaluator_key_store
                .require_production_replay_material()
                .is_err()
        {
            return Err(RefusalReason::WrongContext);
        }

        let mut ordered_participant_identities = Vec::with_capacity(participant_count);
        let sharing_limb_count = selected_sharing_data_prime_coordinates()
            .map_err(|error| error.refusal_reason)?
            .len();
        let mut ordered_degree_zero_commitment_roots = Vec::with_capacity(
            participant_count
                .checked_mul(sharing_limb_count)
                .ok_or(RefusalReason::OutsideSupportedProfile)?,
        );
        for roster_index in 0..participant_count {
            let roster_position =
                u16::try_from(roster_index).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let same_secret = &ordered_same_secret_terminals[roster_index];
            let public_key_share = &ordered_public_key_share_terminals[roster_index];
            let evaluator_source = &evaluator_source_catalog.ordered_participants()[roster_index];
            let expected_participant_identity = same_secret.participant_identity();
            if !same_secret_matches_context(
                same_secret,
                protocol_version,
                suite_identifier,
                manifest_hash,
                ceremony_context_hash,
                action_context_hash,
                roster_hash,
                setup_proof_context_hash,
            ) || same_secret.roster_position() != roster_position
                || same_secret.ordered_degree_zero_commitment_roots().len() != sharing_limb_count
                || !public_key_share_matches_context(
                    public_key_share,
                    protocol_version,
                    suite_identifier,
                    manifest_hash,
                    ceremony_context_hash,
                    action_context_hash,
                    roster_hash,
                    setup_proof_context_hash,
                )
                || public_key_share.roster_position() != roster_position
                || public_key_share.participant_identity() != expected_participant_identity
                || public_key_share.anchor_commitment_roots()
                    != same_secret.anchor_commitment_roots()
                || public_key_share.public_key_share_root()
                    != collective_public_key_terminal.ordered_public_key_share_roots()[roster_index]
                || relinearization_aggregate.ordered_participant_identities()[roster_index]
                    != expected_participant_identity
                || relinearization_aggregate.ordered_anchor_commitment_roots()[roster_index]
                    != same_secret.anchor_commitment_roots()
                || evaluator_source.relinearization().participant_identity()
                    != expected_participant_identity
                || evaluator_source.relinearization().roster_position() != roster_position
                || evaluator_source.relinearization().anchor_commitment_roots()
                    != same_secret.anchor_commitment_roots()
                || evaluator_source.galois().participant_identity() != expected_participant_identity
                || evaluator_source.galois().roster_position() != roster_position
                || evaluator_source.galois().anchor_commitment_roots()
                    != same_secret.anchor_commitment_roots()
                || ordered_participant_identities.contains(&expected_participant_identity)
            {
                return Err(RefusalReason::WrongContext);
            }
            ordered_participant_identities.push(expected_participant_identity);
            ordered_degree_zero_commitment_roots
                .extend_from_slice(same_secret.ordered_degree_zero_commitment_roots());
        }

        let expected_proof_count = selected_public_proof_slots.len();
        let mut ordered_proof_stream_descriptors = Vec::with_capacity(expected_proof_count);
        let mut ordered_observed_proof_slots = Vec::with_capacity(expected_proof_count);
        for terminal in ordered_same_secret_terminals {
            ordered_proof_stream_descriptors.push(terminal.proof_stream_descriptor().clone());
            ordered_observed_proof_slots.push(ObservedVerifiedAcceptedSetupPublicProofSlot::new(
                ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                Some(terminal.roster_position()),
                None,
            ));
        }
        for terminal in ordered_public_key_share_terminals {
            ordered_proof_stream_descriptors.push(terminal.proof_stream_descriptor().clone());
            ordered_observed_proof_slots.push(ObservedVerifiedAcceptedSetupPublicProofSlot::new(
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(terminal.roster_position()),
                None,
            ));
        }
        ordered_proof_stream_descriptors.push(
            collective_public_key_terminal
                .proof_stream_descriptor()
                .clone(),
        );
        ordered_observed_proof_slots.push(ObservedVerifiedAcceptedSetupPublicProofSlot::new(
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            None,
            None,
        ));
        for (roster_position, descriptor) in relinearization_aggregate
            .ordered_round_one_proof_stream_descriptors()
            .iter()
            .enumerate()
        {
            ordered_proof_stream_descriptors.push(descriptor.clone());
            ordered_observed_proof_slots.push(ObservedVerifiedAcceptedSetupPublicProofSlot::new(
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(
                    u16::try_from(roster_position)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?,
                ),
                Some(relinearization_aggregate.schedule_position()),
            ));
        }
        ordered_proof_stream_descriptors
            .push(relinearization_aggregate.proof_stream_descriptor().clone());
        ordered_observed_proof_slots.push(ObservedVerifiedAcceptedSetupPublicProofSlot::new(
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            None,
            Some(relinearization_aggregate.schedule_position()),
        ));
        for participant in evaluator_source_catalog.ordered_participants() {
            let relinearization = participant.relinearization();
            ordered_proof_stream_descriptors
                .push(relinearization.proof_stream_descriptor().clone());
            ordered_observed_proof_slots.push(ObservedVerifiedAcceptedSetupPublicProofSlot::new(
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
                Some(relinearization.roster_position()),
                Some(relinearization.schedule_position()),
            ));
        }
        for participant in evaluator_source_catalog.ordered_participants() {
            let galois = participant.galois();
            ordered_proof_stream_descriptors.push(galois.proof_stream_descriptor().clone());
            ordered_observed_proof_slots.push(ObservedVerifiedAcceptedSetupPublicProofSlot::new(
                ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(galois.roster_position()),
                Some(galois.batch_schedule_position()),
            ));
        }
        ordered_proof_stream_descriptors.push(
            verified_evaluator_key_store
                .proof_stream_descriptor()
                .map_err(|_| RefusalReason::MissingPrerequisite)?
                .clone(),
        );
        ordered_observed_proof_slots.push(ObservedVerifiedAcceptedSetupPublicProofSlot::new(
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            None,
            None,
        ));
        if !descriptor_inventory_is_exact(&ordered_proof_stream_descriptors, expected_proof_count)
            || !proof_slot_inventory_is_exact(
                &selected_public_proof_slots,
                &ordered_observed_proof_slots,
            )
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        Ok(VerifiedAcceptedSetupPublicProofCatalogPreflight {
            protocol_version,
            suite_identifier,
            manifest_hash,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            setup_proof_context_hash,
            ordered_participant_identities: ordered_participant_identities.into_boxed_slice(),
            ordered_degree_zero_commitment_roots: ordered_degree_zero_commitment_roots
                .into_boxed_slice(),
            ordered_proof_stream_descriptors: ordered_proof_stream_descriptors.into_boxed_slice(),
        })
    }

    pub(super) fn from_preflighted_family_terminals(
        preflight: VerifiedAcceptedSetupPublicProofCatalogPreflight,
        collective_public_key_terminal: VerifiedCollectivePublicKeyTerminal,
        verified_evaluator_key_store: VerifiedEvaluatorKeyStore,
    ) -> Self {
        Self {
            protocol_version: preflight.protocol_version,
            suite_identifier: preflight.suite_identifier,
            manifest_hash: preflight.manifest_hash,
            ceremony_context_hash: preflight.ceremony_context_hash,
            action_context_hash: preflight.action_context_hash,
            roster_hash: preflight.roster_hash,
            setup_proof_context_hash: preflight.setup_proof_context_hash,
            ordered_participant_identities: preflight.ordered_participant_identities,
            ordered_degree_zero_commitment_roots: preflight.ordered_degree_zero_commitment_roots,
            ordered_proof_stream_descriptors: preflight.ordered_proof_stream_descriptors,
            collective_public_key_terminal,
            verified_evaluator_key_store,
        }
    }

    pub(super) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(super) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(super) const fn manifest_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.manifest_hash
    }

    pub(super) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(super) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(super) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(super) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(super) fn ordered_participant_identities(&self) -> &[[u8; Hash512::BYTE_LENGTH]] {
        &self.ordered_participant_identities
    }

    pub(super) fn degree_zero_commitment_roots_for_participant(
        &self,
        roster_position: usize,
    ) -> Option<&[[u8; Hash512::BYTE_LENGTH]]> {
        let sharing_limb_count = selected_sharing_data_prime_coordinates().ok()?.len();
        let start = roster_position.checked_mul(sharing_limb_count)?;
        let end = start.checked_add(sharing_limb_count)?;
        self.ordered_degree_zero_commitment_roots.get(start..end)
    }

    pub(super) fn ordered_proof_stream_descriptors(&self) -> &[StreamDescriptor] {
        &self.ordered_proof_stream_descriptors
    }

    pub(super) const fn collective_public_key_terminal(
        &self,
    ) -> &VerifiedCollectivePublicKeyTerminal {
        &self.collective_public_key_terminal
    }

    pub(super) const fn verified_evaluator_key_store(&self) -> &VerifiedEvaluatorKeyStore {
        &self.verified_evaluator_key_store
    }

    pub(super) fn into_authority_material(
        self,
    ) -> (
        VerifiedCollectivePublicKeyTerminal,
        VerifiedEvaluatorKeyStore,
    ) {
        (
            self.collective_public_key_terminal,
            self.verified_evaluator_key_store,
        )
    }
}

fn descriptor_inventory_is_exact(
    ordered_descriptors: &[StreamDescriptor],
    expected_proof_count: usize,
) -> bool {
    ordered_descriptors.len() == expected_proof_count
        && !ordered_descriptors
            .iter()
            .enumerate()
            .any(|(ordinal, descriptor)| ordered_descriptors[..ordinal].contains(descriptor))
}

fn proof_slot_inventory_is_exact(
    selected_slots: &[SelectedAcceptedSetupPublicProofSlot],
    observed_slots: &[ObservedVerifiedAcceptedSetupPublicProofSlot],
) -> bool {
    selected_slots.len() == observed_slots.len()
        && selected_slots
            .iter()
            .zip(observed_slots)
            .all(|(selected_slot, observed_slot)| {
                selected_slot.application_statement_schema_identifier()
                    == observed_slot.application_statement_schema_identifier
                    && selected_slot.roster_position() == observed_slot.roster_position
                    && selected_slot.schedule_position() == observed_slot.schedule_position
            })
}

#[allow(clippy::too_many_arguments)]
fn same_secret_matches_context(
    terminal: &VerifiedSameSecretTerminal,
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
) -> bool {
    terminal.protocol_version() == protocol_version
        && terminal.suite_identifier() == suite_identifier
        && terminal.manifest_hash() == manifest_hash
        && terminal.ceremony_context_hash() == ceremony_context_hash
        && terminal.action_context_hash() == action_context_hash
        && terminal.roster_hash() == roster_hash
        && terminal.setup_proof_context_hash() == setup_proof_context_hash
}

#[allow(clippy::too_many_arguments)]
fn public_key_share_matches_context(
    terminal: &VerifiedPublicKeyShareTerminal,
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
) -> bool {
    terminal.protocol_version() == protocol_version
        && terminal.suite_identifier() == suite_identifier
        && terminal.manifest_hash() == manifest_hash
        && terminal.ceremony_context_hash() == ceremony_context_hash
        && terminal.action_context_hash() == action_context_hash
        && terminal.roster_hash() == roster_hash
        && terminal.setup_proof_context_hash() == setup_proof_context_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(ordinal: usize) -> StreamDescriptor {
        let mut chunk_digest = [0x41; Hash512::BYTE_LENGTH];
        chunk_digest[..8].copy_from_slice(
            &u64::try_from(ordinal)
                .expect("test ordinal fits u64")
                .to_le_bytes(),
        );
        let mut object_digest = [0x81; Hash512::BYTE_LENGTH];
        object_digest[..8].copy_from_slice(
            &u64::try_from(ordinal)
                .expect("test ordinal fits u64")
                .to_le_bytes(),
        );
        StreamDescriptor::new(
            1,
            vec![Hash512::from_bytes(chunk_digest)],
            Hash512::from_bytes(object_digest),
        )
        .expect("test descriptor is canonical")
    }

    #[test]
    fn exact_inventory_rejects_omission_duplicate_and_reordered_terminal_proofs() {
        let selected_slots =
            selected_accepted_setup_public_proof_slots().expect("selected proof slots derive");
        let expected_proof_count = selected_slots.len();
        let mut observed_slots = selected_slots
            .iter()
            .map(|slot| {
                ObservedVerifiedAcceptedSetupPublicProofSlot::new(
                    slot.application_statement_schema_identifier(),
                    slot.roster_position(),
                    slot.schedule_position(),
                )
            })
            .collect::<Vec<_>>();
        assert!(proof_slot_inventory_is_exact(
            &selected_slots,
            &observed_slots
        ));
        observed_slots.swap(1, expected_proof_count - 2);
        assert!(!proof_slot_inventory_is_exact(
            &selected_slots,
            &observed_slots
        ));

        let mut descriptors = (0..expected_proof_count)
            .map(descriptor)
            .collect::<Vec<_>>();
        assert!(descriptor_inventory_is_exact(
            &descriptors,
            expected_proof_count
        ));

        let omitted = descriptors.pop().expect("inventory is nonempty");
        assert!(!descriptor_inventory_is_exact(
            &descriptors,
            expected_proof_count
        ));
        descriptors.push(omitted);
        assert!(expected_proof_count >= 2);
        let duplicate_destination = expected_proof_count / 2;
        descriptors[duplicate_destination] = descriptors[0].clone();
        assert!(!descriptor_inventory_is_exact(
            &descriptors,
            expected_proof_count
        ));
    }
}
