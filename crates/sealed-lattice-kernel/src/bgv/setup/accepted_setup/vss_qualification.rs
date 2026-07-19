use crate::{
    bgv::proof_suite::{CommittedMaterialContext, CommittedMaterialRole},
    foundation::{
        FOUNDATION_PROFILE, RefusalReason, selected_sharing_data_prime_coordinates,
        selected_target_data_prime_coordinates,
    },
};

use super::{
    authority::{
        BrowserOwnedAggregateThresholdShareLimb, VerifiedAcceptedSetupParticipantReleaseMaterial,
        VerifiedAcceptedSetupParticipantTargetReleaseSource,
    },
    generated_mailbox_byte_lengths::VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog,
    verified_public_randomness::VerifiedPublicRandomness,
    verified_terminals::{
        VerifiedAggregateThresholdShareTerminal, VerifiedVssQualificationTerminals,
        VerifiedVssShareLinkageTerminal,
    },
};

/// One opaque VSS qualification handoff consumed by accepted-setup
/// finalization. It retains all sharing-basis roots for every participant and
/// exactly one browser-local target-basis opening source. When a development
/// harness supplied the complete positively verified mailbox corpus, the same
/// handoff also owns its non-serialized exact byte-length catalog. Absence of
/// that optional evidence does not affect qualification. No second registry
/// or caller-provided root catalog can construct this authority.
pub(in crate::bgv) struct VerifiedAcceptedSetupVssQualification {
    public_randomness: VerifiedPublicRandomness,
    qualification_terminals: VerifiedVssQualificationTerminals,
    participant_release_materials: Vec<VerifiedAcceptedSetupParticipantReleaseMaterial>,
    local_target_release_source: VerifiedAcceptedSetupParticipantTargetReleaseSource,
    private_vss_mailbox_byte_lengths:
        Option<VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog>,
}

impl VerifiedAcceptedSetupVssQualification {
    pub(in crate::bgv) fn from_verified_terminals(
        public_randomness: VerifiedPublicRandomness,
        ordered_dealer_terminals: Vec<VerifiedVssShareLinkageTerminal>,
        ordered_recipient_terminals: Vec<VerifiedAggregateThresholdShareTerminal>,
        local_target_release_limbs: Vec<BrowserOwnedAggregateThresholdShareLimb>,
        private_vss_mailbox_byte_lengths: Option<
            VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog,
        >,
    ) -> Result<Self, RefusalReason> {
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let selected_sharing_coordinates =
            selected_sharing_data_prime_coordinates().map_err(|error| error.refusal_reason)?;
        let selected_target_coordinates =
            selected_target_data_prime_coordinates().map_err(|error| error.refusal_reason)?;
        if ordered_dealer_terminals.len() != participant_count
            || ordered_recipient_terminals.len() != participant_count
            || selected_sharing_coordinates != selected_target_coordinates
            || local_target_release_limbs.len() != selected_target_coordinates.len()
            || local_target_release_limbs
                .iter()
                .zip(selected_target_coordinates.iter())
                .any(|(limb, (data_modulus_index, _))| {
                    limb.data_modulus_index() != *data_modulus_index
                })
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }

        let first_local_limb = local_target_release_limbs
            .first()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let first_data_modulus_index = selected_target_coordinates[0].0;
        let local_recipient_position = unique_local_recipient_position(
            &ordered_recipient_terminals,
            first_data_modulus_index,
            first_local_limb.material_context_hash(),
        )?;
        let local_target_release_source =
            VerifiedAcceptedSetupParticipantTargetReleaseSource::from_verified_aggregate_threshold_share(
                &ordered_recipient_terminals[local_recipient_position],
                local_target_release_limbs,
            )
            .map_err(|_| RefusalReason::WrongHashOrRoot)?;
        let participant_release_materials = ordered_recipient_terminals
            .iter()
            .map(
                VerifiedAcceptedSetupParticipantReleaseMaterial::from_verified_aggregate_threshold_share,
            )
            .collect::<Vec<_>>();
        let qualification_terminals = VerifiedVssQualificationTerminals::from_verified_terminals(
            &public_randomness,
            ordered_dealer_terminals,
            ordered_recipient_terminals,
        )?;
        if let Some(mailbox_byte_lengths) = private_vss_mailbox_byte_lengths.as_ref() {
            mailbox_byte_lengths
                .require_matches_verified_qualification(&qualification_terminals)?;
        }

        Ok(Self {
            public_randomness,
            qualification_terminals,
            participant_release_materials,
            local_target_release_source,
            private_vss_mailbox_byte_lengths,
        })
    }

    pub(super) fn into_finalization_parts(
        self,
    ) -> (
        VerifiedPublicRandomness,
        VerifiedVssQualificationTerminals,
        Vec<VerifiedAcceptedSetupParticipantReleaseMaterial>,
        VerifiedAcceptedSetupParticipantTargetReleaseSource,
        Option<VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog>,
    ) {
        (
            self.public_randomness,
            self.qualification_terminals,
            self.participant_release_materials,
            self.local_target_release_source,
            self.private_vss_mailbox_byte_lengths,
        )
    }

    pub(in crate::bgv) const fn verified_public_randomness(&self) -> &VerifiedPublicRandomness {
        &self.public_randomness
    }

    pub(in crate::bgv) const fn qualification_terminals(
        &self,
    ) -> &VerifiedVssQualificationTerminals {
        &self.qualification_terminals
    }

    pub(super) fn participant_release_materials(
        &self,
    ) -> &[VerifiedAcceptedSetupParticipantReleaseMaterial] {
        &self.participant_release_materials
    }

    pub(super) const fn local_target_release_source(
        &self,
    ) -> &VerifiedAcceptedSetupParticipantTargetReleaseSource {
        &self.local_target_release_source
    }
}

fn unique_local_recipient_position(
    ordered_recipient_terminals: &[VerifiedAggregateThresholdShareTerminal],
    first_data_modulus_index: u16,
    first_material_context_hash: [u8; 64],
) -> Result<usize, RefusalReason> {
    let mut matching_position = None;
    for (recipient_position, terminal) in ordered_recipient_terminals.iter().enumerate() {
        let expected_context_hash = CommittedMaterialContext::new(
            terminal.suite_identifier(),
            terminal.ceremony_context_hash(),
            terminal.action_context_hash(),
            terminal.participant_identity(),
            CommittedMaterialRole::AggregateThresholdShare,
            first_data_modulus_index,
            terminal.roster_position(),
        )
        .context_hash()
        .map_err(|_| RefusalReason::WrongContext)?;
        if expected_context_hash == first_material_context_hash {
            if matching_position.replace(recipient_position).is_some() {
                return Err(RefusalReason::WrongContext);
            }
        }
    }
    matching_position.ok_or(RefusalReason::WrongContext)
}
