use crate::{
    bgv::proof_suite::{
        SelectedEvaluatorEntryPosition, SelectedEvaluatorStoreSource,
        SelectedEvaluatorStoreSourceCatalog, VerifiedGaloisSourceMaterialBatch,
        VerifiedKeySwitchComponentMaterial, VerifiedRelinearizationAggregateMaterial,
        VerifiedRelinearizationSourceMaterial,
    },
    foundation::{CanonicalStreamReadbackVerifier, FOUNDATION_PROFILE, Hash512, RefusalReason},
};

pub(super) struct VerifiedAcceptedSetupParticipantEvaluatorSource {
    relinearization: VerifiedRelinearizationSourceMaterial,
    galois: VerifiedGaloisSourceMaterialBatch,
}

impl VerifiedAcceptedSetupParticipantEvaluatorSource {
    pub(super) const fn from_verified_sources(
        relinearization: VerifiedRelinearizationSourceMaterial,
        galois: VerifiedGaloisSourceMaterialBatch,
    ) -> Self {
        Self {
            relinearization,
            galois,
        }
    }

    pub(super) const fn relinearization(&self) -> &VerifiedRelinearizationSourceMaterial {
        &self.relinearization
    }

    pub(super) const fn galois(&self) -> &VerifiedGaloisSourceMaterialBatch {
        &self.galois
    }
}

/// Exact verifier-owned evaluator source catalog for one accepted setup. Each
/// participant contributes one 0x1216 relinearization source and one suite-
/// fixed 0x1217 Galois batch, both proved against the same three secret-anchor
/// roots. There is no projection to the removed diagonal key material.
pub(crate) struct VerifiedAcceptedSetupEvaluatorSourceCatalog {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
    ordered_participants: Box<[VerifiedAcceptedSetupParticipantEvaluatorSource]>,
}

/// Allocation-complete borrowed validation for one evaluator source catalog.
/// The assembly retains every opaque family authority until this preflight
/// succeeds, so a malformed cross-family join cannot consume a retryable
/// verifier result.
pub(super) struct VerifiedAcceptedSetupEvaluatorSourceCatalogPreflight {
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    action_context_hash: [u8; Hash512::BYTE_LENGTH],
    manifest_hash: [u8; Hash512::BYTE_LENGTH],
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    setup_proof_context_hash: [u8; Hash512::BYTE_LENGTH],
}

impl VerifiedAcceptedSetupEvaluatorSourceCatalog {
    pub(super) fn preflight_from_verified_participant_sources(
        expected_ordered_participant_identities: &[[u8; Hash512::BYTE_LENGTH]],
        expected_manifest_hash: [u8; Hash512::BYTE_LENGTH],
        expected_roster_hash: [u8; Hash512::BYTE_LENGTH],
        relinearization_aggregate: &VerifiedRelinearizationAggregateMaterial,
        ordered_sources: &[(
            &VerifiedRelinearizationSourceMaterial,
            &VerifiedGaloisSourceMaterialBatch,
        )],
    ) -> Result<VerifiedAcceptedSetupEvaluatorSourceCatalogPreflight, RefusalReason> {
        if expected_ordered_participant_identities.len()
            != usize::from(FOUNDATION_PROFILE.participant_count)
            || ordered_sources.len() != expected_ordered_participant_identities.len()
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let (first_relinearization, first_galois) = ordered_sources
            .first()
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let protocol_version = first_relinearization.protocol_version();
        let suite_identifier = first_relinearization.suite_identifier();
        let ceremony_context_hash = first_relinearization.ceremony_context_hash();
        let action_context_hash = first_relinearization.action_context_hash();
        let setup_proof_context_hash = first_relinearization.setup_proof_context_hash();
        if protocol_version != FOUNDATION_PROFILE.protocol_version
            || first_relinearization.roster_hash() != expected_roster_hash
            || first_galois.protocol_version() != protocol_version
            || first_galois.suite_identifier() != suite_identifier
            || first_galois.ceremony_context_hash() != ceremony_context_hash
            || first_galois.action_context_hash() != action_context_hash
            || first_galois.roster_hash() != expected_roster_hash
            || first_galois.setup_proof_context_hash() != setup_proof_context_hash
            || relinearization_aggregate.protocol_version() != protocol_version
            || relinearization_aggregate.suite_identifier() != suite_identifier
            || relinearization_aggregate.ceremony_context_hash() != ceremony_context_hash
            || relinearization_aggregate.action_context_hash() != action_context_hash
            || relinearization_aggregate.roster_hash() != expected_roster_hash
            || relinearization_aggregate.setup_proof_context_hash() != setup_proof_context_hash
            || relinearization_aggregate.ordered_source_root_pairs().len()
                != expected_ordered_participant_identities.len()
        {
            return Err(RefusalReason::WrongContext);
        }

        for (roster_index, expected_identity) in
            expected_ordered_participant_identities.iter().enumerate()
        {
            let (relinearization, galois) = ordered_sources
                .get(roster_index)
                .copied()
                .ok_or(RefusalReason::MissingPrerequisite)?;
            let roster_position =
                u16::try_from(roster_index).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
            let expected_round_one_root_pair = relinearization_aggregate
                .ordered_source_root_pairs()
                .get(roster_index)
                .ok_or(RefusalReason::MissingPrerequisite)?;
            if relinearization.protocol_version() != protocol_version
                || relinearization.suite_identifier() != suite_identifier
                || relinearization.ceremony_context_hash() != ceremony_context_hash
                || relinearization.action_context_hash() != action_context_hash
                || relinearization.roster_hash() != expected_roster_hash
                || relinearization.setup_proof_context_hash() != setup_proof_context_hash
                || relinearization.participant_identity() != *expected_identity
                || relinearization.roster_position() != roster_position
                || relinearization.schedule_position()
                    != relinearization_aggregate.schedule_position()
                || relinearization.round_one_left_root() != expected_round_one_root_pair[0]
                || relinearization.round_one_right_root() != expected_round_one_root_pair[1]
                || relinearization.aggregate_round_one_left_root()
                    != relinearization_aggregate.aggregate_left_root()
                || relinearization.aggregate_round_one_right_root()
                    != relinearization_aggregate.aggregate_right_root()
                || galois.protocol_version() != protocol_version
                || galois.suite_identifier() != suite_identifier
                || galois.ceremony_context_hash() != ceremony_context_hash
                || galois.action_context_hash() != action_context_hash
                || galois.roster_hash() != expected_roster_hash
                || galois.setup_proof_context_hash() != setup_proof_context_hash
                || galois.participant_identity() != *expected_identity
                || galois.roster_position() != roster_position
                || galois.anchor_commitment_roots() != relinearization.anchor_commitment_roots()
                || galois.ordered_auxiliary_roots() != first_galois.ordered_auxiliary_roots()
            {
                return Err(RefusalReason::WrongContext);
            }
        }

        Ok(VerifiedAcceptedSetupEvaluatorSourceCatalogPreflight {
            protocol_version,
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            manifest_hash: expected_manifest_hash,
            roster_hash: expected_roster_hash,
            setup_proof_context_hash,
        })
    }

    pub(super) fn from_preflighted_participant_sources(
        preflight: VerifiedAcceptedSetupEvaluatorSourceCatalogPreflight,
        ordered_participants: Vec<VerifiedAcceptedSetupParticipantEvaluatorSource>,
    ) -> Self {
        Self {
            protocol_version: preflight.protocol_version,
            suite_identifier: preflight.suite_identifier,
            ceremony_context_hash: preflight.ceremony_context_hash,
            action_context_hash: preflight.action_context_hash,
            manifest_hash: preflight.manifest_hash,
            roster_hash: preflight.roster_hash,
            setup_proof_context_hash: preflight.setup_proof_context_hash,
            ordered_participants: ordered_participants.into_boxed_slice(),
        }
    }

    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    pub(crate) const fn manifest_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.manifest_hash
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    pub(crate) fn matches_ordered_participant_identities(
        &self,
        expected_ordered_participant_identities: &[[u8; Hash512::BYTE_LENGTH]],
    ) -> bool {
        self.ordered_participants.len() == expected_ordered_participant_identities.len()
            && self
                .ordered_participants
                .iter()
                .zip(expected_ordered_participant_identities)
                .all(|(participant, expected_identity)| {
                    participant.relinearization().participant_identity() == *expected_identity
                        && participant.galois().participant_identity() == *expected_identity
                })
    }

    pub(super) fn ordered_participants(
        &self,
    ) -> &[VerifiedAcceptedSetupParticipantEvaluatorSource] {
        &self.ordered_participants
    }

    pub(crate) fn component_material(
        &self,
        roster_position: u16,
        evaluator_position: SelectedEvaluatorEntryPosition,
    ) -> Option<&VerifiedKeySwitchComponentMaterial> {
        let participant = self
            .ordered_participants
            .get(usize::from(roster_position))?;
        if participant.relinearization().evaluator_position() == evaluator_position {
            return Some(participant.relinearization().material());
        }
        participant
            .galois()
            .ordered_components()
            .iter()
            .find(|component| component.evaluator_position() == evaluator_position)
            .map(|component| component.material())
    }

    pub(crate) fn component_root(
        &self,
        roster_position: u16,
        evaluator_position: SelectedEvaluatorEntryPosition,
    ) -> Option<[u8; Hash512::BYTE_LENGTH]> {
        let participant = self
            .ordered_participants
            .get(usize::from(roster_position))?;
        if participant.relinearization().evaluator_position() == evaluator_position {
            return Some(participant.relinearization().contribution_root());
        }
        participant
            .galois()
            .ordered_components()
            .iter()
            .find(|component| component.evaluator_position() == evaluator_position)
            .map(|component| component.contribution_root())
    }

    pub(crate) fn component_public_polynomial_context_hash(
        &self,
        roster_position: u16,
        evaluator_position: SelectedEvaluatorEntryPosition,
    ) -> Option<[u8; Hash512::BYTE_LENGTH]> {
        let participant = self
            .ordered_participants
            .get(usize::from(roster_position))?;
        if participant.relinearization().evaluator_position() == evaluator_position {
            return Some(
                participant
                    .relinearization()
                    .public_polynomial_context_hash(),
            );
        }
        participant
            .galois()
            .ordered_components()
            .iter()
            .find(|component| component.evaluator_position() == evaluator_position)
            .map(|component| component.public_polynomial_context_hash())
    }

    pub(crate) fn ordered_galois_auxiliary_roots(
        &self,
    ) -> Option<&[crate::bgv::proof_suite::VerifiedEvaluatorAuxiliaryRoot]> {
        self.ordered_participants
            .first()
            .map(|participant| participant.galois().ordered_auxiliary_roots())
    }
}

impl SelectedEvaluatorStoreSourceCatalog for VerifiedAcceptedSetupEvaluatorSourceCatalog {
    fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.suite_identifier
    }

    fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.ceremony_context_hash
    }

    fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.action_context_hash
    }

    fn manifest_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.manifest_hash
    }

    fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.roster_hash
    }

    fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.setup_proof_context_hash
    }

    fn component_source(
        &self,
        roster_position: u16,
        evaluator_position: SelectedEvaluatorEntryPosition,
    ) -> Result<Option<SelectedEvaluatorStoreSource>, RefusalReason> {
        let Some(material) = self.component_material(roster_position, evaluator_position) else {
            return Ok(None);
        };
        let readback: CanonicalStreamReadbackVerifier = material.begin_authenticated_readback()?;
        Ok(Some(SelectedEvaluatorStoreSource::from_authenticated_authority(
            material.topology().clone(),
            material.material_root().into_bytes(),
            material.stream_descriptor().clone(),
            readback,
        )))
    }

    fn component_root(
        &self,
        roster_position: u16,
        evaluator_position: SelectedEvaluatorEntryPosition,
    ) -> Option<[u8; Hash512::BYTE_LENGTH]> {
        VerifiedAcceptedSetupEvaluatorSourceCatalog::component_root(
            self,
            roster_position,
            evaluator_position,
        )
    }

    fn component_public_polynomial_context_hash(
        &self,
        roster_position: u16,
        evaluator_position: SelectedEvaluatorEntryPosition,
    ) -> Option<[u8; Hash512::BYTE_LENGTH]> {
        VerifiedAcceptedSetupEvaluatorSourceCatalog::component_public_polynomial_context_hash(
            self,
            roster_position,
            evaluator_position,
        )
    }
}
