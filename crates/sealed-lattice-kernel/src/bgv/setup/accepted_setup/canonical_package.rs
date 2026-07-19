use core::fmt;
use std::collections::BTreeSet;

use crate::bgv::{
    evaluator::candidate_evidence::EvaluatorCandidateInput,
    proof_suite::selected_galois_key_share_batch_schedule,
};
use crate::foundation::{
    CanonicalCodecError, CanonicalCodecErrorKind, CanonicalDecodeLimits, CanonicalItem,
    CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE, FoundationSchemaError, Hash512,
    ParticipantIdentity, ProofApplicationSlotCeilings, RefusalReason, StateCapabilityKind,
    StreamDescriptor, VerifiedStateReservation, hash_foundation_tuple_512,
};

const ACCEPTED_SETUP_PACKAGE_SCHEMA_IDENTIFIER: u16 = 0x1205;
const ACCEPTED_SETUP_PACKAGE_SCHEMA_VERSION: u16 = 1;
const ACCEPTED_SETUP_PACKAGE_FIELD_COUNT: usize = 8;
const ACCEPTED_SETUP_PACKAGE_HASH_DOMAIN: &str = "sealed-lattice/setup/package/v1";
const SETUP_TERMINAL_PACKAGE_AUTHORIZATION_DOMAIN: &str =
    "sealed-lattice/setup/state/terminal-package/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::bgv) struct AcceptedSetupPackageError {
    pub(in crate::bgv) refusal_reason: RefusalReason,
    message: &'static str,
}

impl AcceptedSetupPackageError {
    const fn new(refusal_reason: RefusalReason, message: &'static str) -> Self {
        Self {
            refusal_reason,
            message,
        }
    }
}

impl fmt::Display for AcceptedSetupPackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for AcceptedSetupPackageError {}

impl From<CanonicalCodecError> for AcceptedSetupPackageError {
    fn from(error: CanonicalCodecError) -> Self {
        let refusal_reason = if error.kind == CanonicalCodecErrorKind::LimitExceeded {
            RefusalReason::OutsideSupportedProfile
        } else {
            RefusalReason::MalformedEncoding
        };
        Self::new(refusal_reason, "accepted setup package is not canonical")
    }
}

impl From<FoundationSchemaError> for AcceptedSetupPackageError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::new(
            error.refusal_reason,
            "accepted setup package contains an invalid selected binding",
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::bgv) struct SelectedAcceptedSetupPublicProofSlot {
    application_statement_schema_identifier: u16,
    roster_position: Option<u16>,
    schedule_position: Option<u32>,
}

impl SelectedAcceptedSetupPublicProofSlot {
    pub(in crate::bgv) const fn application_statement_schema_identifier(&self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(in crate::bgv) const fn roster_position(&self) -> Option<u16> {
        self.roster_position
    }

    pub(in crate::bgv) const fn schedule_position(&self) -> Option<u32> {
        self.schedule_position
    }
}

/// Canonical setup-package source decoded from exact schema `0x1205` bytes.
///
/// The package intentionally carries no ceremony context of its own. The
/// successful setup terminal obtains that authority from positive setup
/// verification sources and uses this value only for the ordered object and
/// stream inventory committed by `setup_package_hash`.
#[derive(Debug)]
pub(in crate::bgv) struct CanonicalAcceptedSetupPackage {
    setup_package_hash: Hash512,
    canonical_package_byte_length: u64,
    ordered_hash_list_carrier_byte_lengths: [u64; 5],
    setup_intent_object_hashes: Box<[Hash512]>,
    public_randomness_commitment_object_hashes: Box<[Hash512]>,
    public_randomness_reveal_object_hashes: Box<[Hash512]>,
    dealer_public_record_object_hashes: Box<[Hash512]>,
    private_share_acceptance_object_hashes: Box<[Hash512]>,
    collective_public_key_descriptor: StreamDescriptor,
    evaluator_key_store_descriptor: StreamDescriptor,
    ordered_proof_descriptors: Box<[StreamDescriptor]>,
}

impl CanonicalAcceptedSetupPackage {
    /// Encodes the exact selected package inventory from verifier-owned
    /// sources. Callers cannot use this constructor to bypass positive source
    /// checks because it remains private to the accepted-setup implementation;
    /// the capability builder is the only production caller.
    pub(super) fn encode_authoritative_inventory(
        setup_intent_object_hashes: &[Hash512],
        public_randomness_commitment_object_hashes: &[Hash512],
        public_randomness_reveal_object_hashes: &[Hash512],
        dealer_public_record_object_hashes: &[Hash512],
        private_share_acceptance_object_hashes: &[Hash512],
        collective_public_key_descriptor: &StreamDescriptor,
        evaluator_key_store_descriptor: &StreamDescriptor,
        ordered_proof_descriptors: &[StreamDescriptor],
    ) -> Result<Vec<u8>, AcceptedSetupPackageError> {
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        if [
            setup_intent_object_hashes.len(),
            public_randomness_commitment_object_hashes.len(),
            public_randomness_reveal_object_hashes.len(),
            dealer_public_record_object_hashes.len(),
            private_share_acceptance_object_hashes.len(),
        ]
        .into_iter()
        .any(|count| count != participant_count)
            || ordered_proof_descriptors.len()
                != selected_accepted_setup_public_proof_slots()?.len()
        {
            return Err(AcceptedSetupPackageError::new(
                RefusalReason::WrongTypeOrLength,
                "accepted setup package authoritative inventory has the wrong count",
            ));
        }

        let limits = CanonicalDecodeLimits::default();
        let collective_descriptor_item =
            nested_stream_descriptor_item(collective_public_key_descriptor, &limits)?;
        let evaluator_descriptor_item =
            nested_stream_descriptor_item(evaluator_key_store_descriptor, &limits)?;
        let proof_descriptor_items = ordered_proof_descriptors
            .iter()
            .map(|descriptor| nested_stream_descriptor_item(descriptor, &limits))
            .collect::<Result<Vec<_>, _>>()?;
        let canonical_package_bytes = CanonicalTuple::new(
            ACCEPTED_SETUP_PACKAGE_SCHEMA_IDENTIFIER,
            ACCEPTED_SETUP_PACKAGE_SCHEMA_VERSION,
            vec![
                canonical_hash_list(setup_intent_object_hashes)?,
                canonical_hash_list(public_randomness_commitment_object_hashes)?,
                canonical_hash_list(public_randomness_reveal_object_hashes)?,
                canonical_hash_list(dealer_public_record_object_hashes)?,
                canonical_hash_list(private_share_acceptance_object_hashes)?,
                collective_descriptor_item,
                evaluator_descriptor_item,
                CanonicalItem::homogeneous_list(
                    CanonicalItemType::NestedTuple,
                    &proof_descriptor_items,
                )?,
            ],
        )
        .encode()?;
        Self::decode(&canonical_package_bytes, &limits)?;
        Ok(canonical_package_bytes)
    }

    pub(in crate::bgv) fn decode(
        canonical_package_bytes: &[u8],
        limits: &CanonicalDecodeLimits,
    ) -> Result<Self, AcceptedSetupPackageError> {
        let tuple = CanonicalTuple::decode(canonical_package_bytes, limits)?;
        if tuple.schema_identifier != ACCEPTED_SETUP_PACKAGE_SCHEMA_IDENTIFIER
            || tuple.schema_version != ACCEPTED_SETUP_PACKAGE_SCHEMA_VERSION
            || tuple.items.len() != ACCEPTED_SETUP_PACKAGE_FIELD_COUNT
        {
            return Err(AcceptedSetupPackageError::new(
                RefusalReason::WrongTypeOrLength,
                "accepted setup package has the wrong schema, version, or field count",
            ));
        }
        if tuple.encode()? != canonical_package_bytes {
            return Err(AcceptedSetupPackageError::new(
                RefusalReason::MalformedEncoding,
                "accepted setup package does not round-trip canonically",
            ));
        }
        let canonical_package_byte_length =
            u64::try_from(canonical_package_bytes.len()).map_err(|_| {
                AcceptedSetupPackageError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "accepted setup package byte length does not fit u64",
                )
            })?;
        let mut ordered_hash_list_carrier_byte_lengths = [0_u64; 5];
        for (destination, item) in ordered_hash_list_carrier_byte_lengths
            .iter_mut()
            .zip(tuple.items.iter().take(5))
        {
            *destination = u64::try_from(item.canonical_bytes().len()).map_err(|_| {
                AcceptedSetupPackageError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "accepted setup hash-list carrier byte length does not fit u64",
                )
            })?;
        }

        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let setup_intent_object_hashes = read_exact_hash_list(&tuple.items[0], participant_count)?;
        let public_randomness_commitment_object_hashes =
            read_exact_hash_list(&tuple.items[1], participant_count)?;
        let public_randomness_reveal_object_hashes =
            read_exact_hash_list(&tuple.items[2], participant_count)?;
        let dealer_public_record_object_hashes =
            read_exact_hash_list(&tuple.items[3], participant_count)?;
        let private_share_acceptance_object_hashes =
            read_exact_hash_list(&tuple.items[4], participant_count)?;
        let collective_public_key_descriptor = read_stream_descriptor(&tuple.items[5], limits)?;
        let evaluator_key_store_descriptor = read_stream_descriptor(&tuple.items[6], limits)?;
        let ordered_proof_descriptors = read_stream_descriptor_list(&tuple.items[7], limits)?;
        let selected_public_proof_slots = selected_accepted_setup_public_proof_slots()?;
        if ordered_proof_descriptors.len() != selected_public_proof_slots.len() {
            return Err(AcceptedSetupPackageError::new(
                RefusalReason::WrongTypeOrLength,
                "accepted setup package has the wrong selected public-proof inventory",
            ));
        }

        let setup_package_hash = hash_foundation_tuple_512(
            ACCEPTED_SETUP_PACKAGE_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(canonical_package_bytes)?],
        )?;
        Ok(Self {
            setup_package_hash,
            canonical_package_byte_length,
            ordered_hash_list_carrier_byte_lengths,
            setup_intent_object_hashes: setup_intent_object_hashes.into_boxed_slice(),
            public_randomness_commitment_object_hashes: public_randomness_commitment_object_hashes
                .into_boxed_slice(),
            public_randomness_reveal_object_hashes: public_randomness_reveal_object_hashes
                .into_boxed_slice(),
            dealer_public_record_object_hashes: dealer_public_record_object_hashes
                .into_boxed_slice(),
            private_share_acceptance_object_hashes: private_share_acceptance_object_hashes
                .into_boxed_slice(),
            collective_public_key_descriptor,
            evaluator_key_store_descriptor,
            ordered_proof_descriptors: ordered_proof_descriptors.into_boxed_slice(),
        })
    }

    pub(in crate::bgv) const fn setup_package_hash(&self) -> Hash512 {
        self.setup_package_hash
    }

    pub(in crate::bgv) const fn canonical_package_byte_length(&self) -> u64 {
        self.canonical_package_byte_length
    }

    pub(in crate::bgv) const fn ordered_hash_list_carrier_byte_lengths(&self) -> [u64; 5] {
        self.ordered_hash_list_carrier_byte_lengths
    }

    pub(in crate::bgv) fn setup_intent_object_hashes(&self) -> &[Hash512] {
        &self.setup_intent_object_hashes
    }

    pub(in crate::bgv) fn public_randomness_commitment_object_hashes(&self) -> &[Hash512] {
        &self.public_randomness_commitment_object_hashes
    }

    pub(in crate::bgv) fn public_randomness_reveal_object_hashes(&self) -> &[Hash512] {
        &self.public_randomness_reveal_object_hashes
    }

    pub(in crate::bgv) fn dealer_public_record_object_hashes(&self) -> &[Hash512] {
        &self.dealer_public_record_object_hashes
    }

    pub(in crate::bgv) fn private_share_acceptance_object_hashes(&self) -> &[Hash512] {
        &self.private_share_acceptance_object_hashes
    }

    pub(in crate::bgv) const fn collective_public_key_descriptor(&self) -> &StreamDescriptor {
        &self.collective_public_key_descriptor
    }

    pub(in crate::bgv) const fn evaluator_key_store_descriptor(&self) -> &StreamDescriptor {
        &self.evaluator_key_store_descriptor
    }

    pub(in crate::bgv) fn ordered_proof_descriptors(&self) -> &[StreamDescriptor] {
        &self.ordered_proof_descriptors
    }

    pub(in crate::bgv) fn ordered_proof_descriptor_total_byte_lengths(
        &self,
    ) -> impl ExactSizeIterator<Item = u64> + '_ {
        self.ordered_proof_descriptors
            .iter()
            .map(|descriptor| descriptor.total_byte_length)
    }

    pub(in crate::bgv) fn selected_public_proof_slots(
        &self,
    ) -> Result<Vec<SelectedAcceptedSetupPublicProofSlot>, AcceptedSetupPackageError> {
        let slots = selected_accepted_setup_public_proof_slots()?;
        if slots.len() != self.ordered_proof_descriptors.len() {
            return Err(AcceptedSetupPackageError::new(
                RefusalReason::WrongTypeOrLength,
                "accepted setup package has the wrong selected public-proof inventory",
            ));
        }
        Ok(slots)
    }
}

fn canonical_hash_list(hashes: &[Hash512]) -> Result<CanonicalItem, AcceptedSetupPackageError> {
    let items = hashes
        .iter()
        .map(|hash| CanonicalItem::hash512(hash.into_bytes()))
        .collect::<Vec<_>>();
    Ok(CanonicalItem::homogeneous_list(
        CanonicalItemType::Hash512,
        &items,
    )?)
}

fn nested_stream_descriptor_item(
    descriptor: &StreamDescriptor,
    limits: &CanonicalDecodeLimits,
) -> Result<CanonicalItem, AcceptedSetupPackageError> {
    Ok(CanonicalItem::from_canonical_bytes(
        CanonicalItemType::NestedTuple,
        descriptor.encode()?,
        limits,
    )?)
}

/// Positive kind-eight state-reservation facts for one terminal package hash.
///
/// This is process authority, not a serializable package field. Construction
/// requires reservations borrowed inside the accepted-setup state transaction;
/// its owned result can enter the preflighted authority insertion without
/// removing those reservations early.
pub(in crate::bgv) struct VerifiedSetupTerminalReservationSet {
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster_hash: Hash512,
    setup_package_hash: Hash512,
    ordered_subject_participant_identities: Box<[ParticipantIdentity]>,
}

impl VerifiedSetupTerminalReservationSet {
    pub(in crate::bgv) fn from_borrowed_reservations(
        reservations: &[&VerifiedStateReservation],
        roster_hash: Hash512,
        setup_package_hash: Hash512,
    ) -> Result<Self, AcceptedSetupPackageError> {
        if reservations.len() < usize::from(FOUNDATION_PROFILE.finality_quorum)
            || reservations.len() > usize::from(FOUNDATION_PROFILE.participant_count)
        {
            return Err(AcceptedSetupPackageError::new(
                RefusalReason::WrongTypeOrLength,
                "setup terminal reservation set has the wrong cardinality",
            ));
        }
        let first_reservation = reservations.first().ok_or_else(|| {
            AcceptedSetupPackageError::new(
                RefusalReason::WrongTypeOrLength,
                "setup terminal reservation set is empty",
            )
        })?;
        let suite_identifier = first_reservation.suite_id();
        let ceremony_context_hash = first_reservation.ceremony_context_hash();
        let action_context_hash = first_reservation.action_context_hash();
        let expected_authorization_hash = setup_terminal_package_authorization_hash(
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            setup_package_hash,
        )?;
        let mut identities = BTreeSet::new();
        for reservation in reservations {
            if reservation.capability_kind() != StateCapabilityKind::SetupTerminalPackage {
                return Err(AcceptedSetupPackageError::new(
                    RefusalReason::WrongTypeOrLength,
                    "setup terminal reservation has the wrong capability kind",
                ));
            }
            if reservation.suite_id() != suite_identifier
                || reservation.ceremony_context_hash() != ceremony_context_hash
                || reservation.action_context_hash() != action_context_hash
            {
                return Err(AcceptedSetupPackageError::new(
                    RefusalReason::WrongContext,
                    "setup terminal reservations do not share one ceremony binding",
                ));
            }
            if reservation.authorization_hash() != expected_authorization_hash {
                return Err(AcceptedSetupPackageError::new(
                    RefusalReason::WrongHashOrRoot,
                    "setup terminal reservation has the wrong package authorization hash",
                ));
            }
            if !identities.insert(reservation.subject_participant_id()) {
                return Err(AcceptedSetupPackageError::new(
                    RefusalReason::DuplicateIdentity,
                    "setup terminal reservation identities must be distinct",
                ));
            }
        }
        Ok(Self {
            suite_identifier,
            ceremony_context_hash,
            action_context_hash,
            roster_hash,
            setup_package_hash,
            ordered_subject_participant_identities: identities
                .into_iter()
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        })
    }

    pub(in crate::bgv) const fn suite_identifier(&self) -> Hash512 {
        self.suite_identifier
    }

    pub(in crate::bgv) const fn ceremony_context_hash(&self) -> Hash512 {
        self.ceremony_context_hash
    }

    pub(in crate::bgv) const fn action_context_hash(&self) -> Hash512 {
        self.action_context_hash
    }

    pub(in crate::bgv) const fn roster_hash(&self) -> Hash512 {
        self.roster_hash
    }

    pub(in crate::bgv) const fn setup_package_hash(&self) -> Hash512 {
        self.setup_package_hash
    }

    pub(in crate::bgv) fn ordered_subject_participant_identities(&self) -> &[ParticipantIdentity] {
        &self.ordered_subject_participant_identities
    }
}

pub(super) fn setup_terminal_package_authorization_hash(
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster_hash: Hash512,
    setup_package_hash: Hash512,
) -> Result<Hash512, AcceptedSetupPackageError> {
    hash_foundation_tuple_512(
        SETUP_TERMINAL_PACKAGE_AUTHORIZATION_DOMAIN,
        &[
            CanonicalItem::hash512(suite_identifier.into_bytes()),
            CanonicalItem::hash512(ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(action_context_hash.into_bytes()),
            CanonicalItem::hash512(roster_hash.into_bytes()),
            CanonicalItem::hash512(setup_package_hash.into_bytes()),
        ],
    )
    .map_err(AcceptedSetupPackageError::from)
}

pub(super) fn selected_accepted_setup_public_proof_slots()
-> Result<Vec<SelectedAcceptedSetupPublicProofSlot>, AcceptedSetupPackageError> {
    let evaluator_candidate = EvaluatorCandidateInput::implemented().map_err(|_| {
        AcceptedSetupPackageError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "selected evaluator candidate does not derive",
        )
    })?;
    let unique_relinearization_levels = evaluator_candidate
        .relinearization_levels
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if unique_relinearization_levels.len() != evaluator_candidate.relinearization_levels.len() {
        return Err(AcceptedSetupPackageError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "selected relinearization catalog contains a duplicate level",
        ));
    }
    let selected_relinearization_schedule_positions =
        (0..evaluator_candidate.relinearization_levels.len())
            .map(|schedule_position| {
                u32::try_from(schedule_position).map_err(|_| {
                    AcceptedSetupPackageError::new(
                        RefusalReason::OutsideSupportedProfile,
                        "selected relinearization schedule position does not fit u32",
                    )
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
    let selected_galois_batch_schedule_positions = selected_galois_key_share_batch_schedule()
        .into_iter()
        .collect::<BTreeSet<_>>();
    if selected_relinearization_schedule_positions.is_empty()
        || selected_galois_batch_schedule_positions.is_empty()
    {
        return Err(AcceptedSetupPackageError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "selected setup proof schedule is empty",
        ));
    }

    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let mut slots = Vec::new();
    for application_statement_schema_identifier in [
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    ] {
        for roster_position in 0..FOUNDATION_PROFILE.participant_count {
            slots.push(SelectedAcceptedSetupPublicProofSlot {
                application_statement_schema_identifier,
                roster_position: Some(roster_position),
                schedule_position: None,
            });
        }
    }
    slots.push(SelectedAcceptedSetupPublicProofSlot {
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        roster_position: None,
        schedule_position: None,
    });
    append_roster_schedule_slots(
        &mut slots,
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
        &selected_relinearization_schedule_positions,
    );
    for schedule_position in &selected_relinearization_schedule_positions {
        slots.push(SelectedAcceptedSetupPublicProofSlot {
            application_statement_schema_identifier:
                ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            roster_position: None,
            schedule_position: Some(*schedule_position),
        });
    }
    append_roster_schedule_slots(
        &mut slots,
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
        &selected_relinearization_schedule_positions,
    );
    append_roster_schedule_slots(
        &mut slots,
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        &selected_galois_batch_schedule_positions,
    );
    slots.push(SelectedAcceptedSetupPublicProofSlot {
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        roster_position: None,
        schedule_position: None,
    });

    let expected_count = participant_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .and_then(|count| {
            count.checked_add(
                participant_count.checked_mul(selected_relinearization_schedule_positions.len())?,
            )
        })
        .and_then(|count| count.checked_add(selected_relinearization_schedule_positions.len()))
        .and_then(|count| {
            count.checked_add(
                participant_count.checked_mul(selected_relinearization_schedule_positions.len())?,
            )
        })
        .and_then(|count| {
            count.checked_add(
                participant_count.checked_mul(selected_galois_batch_schedule_positions.len())?,
            )
        })
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| {
            AcceptedSetupPackageError::new(
                RefusalReason::OutsideSupportedProfile,
                "selected setup proof inventory count overflows",
            )
        })?;
    if slots.len() != expected_count {
        return Err(AcceptedSetupPackageError::new(
            RefusalReason::UnsupportedVersionOrSuite,
            "selected setup proof inventory is not the exact fixed profile",
        ));
    }
    Ok(slots)
}

fn append_roster_schedule_slots(
    slots: &mut Vec<SelectedAcceptedSetupPublicProofSlot>,
    application_statement_schema_identifier: u16,
    schedule_positions: &BTreeSet<u32>,
) {
    for roster_position in 0..FOUNDATION_PROFILE.participant_count {
        for schedule_position in schedule_positions {
            slots.push(SelectedAcceptedSetupPublicProofSlot {
                application_statement_schema_identifier,
                roster_position: Some(roster_position),
                schedule_position: Some(*schedule_position),
            });
        }
    }
}

fn read_exact_hash_list(
    item: &CanonicalItem,
    expected_count: usize,
) -> Result<Vec<Hash512>, AcceptedSetupPackageError> {
    let (count, payload) = read_list_header(item, CanonicalItemType::Hash512)?;
    let expected_byte_length = count.checked_mul(Hash512::BYTE_LENGTH).ok_or_else(|| {
        AcceptedSetupPackageError::new(
            RefusalReason::OutsideSupportedProfile,
            "accepted setup package hash-list byte length overflows",
        )
    })?;
    if count != expected_count || payload.len() != expected_byte_length {
        return Err(AcceptedSetupPackageError::new(
            RefusalReason::WrongTypeOrLength,
            "accepted setup package hash list has the wrong count or byte length",
        ));
    }
    payload
        .chunks_exact(Hash512::BYTE_LENGTH)
        .map(|bytes| {
            let hash_bytes: [u8; Hash512::BYTE_LENGTH] = bytes.try_into().map_err(|_| {
                AcceptedSetupPackageError::new(
                    RefusalReason::MalformedEncoding,
                    "accepted setup package contains a malformed hash",
                )
            })?;
            Ok(Hash512::from_bytes(hash_bytes))
        })
        .collect()
}

fn read_stream_descriptor(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> Result<StreamDescriptor, AcceptedSetupPackageError> {
    if item.item_type() != CanonicalItemType::NestedTuple {
        return Err(AcceptedSetupPackageError::new(
            RefusalReason::WrongTypeOrLength,
            "accepted setup package stream descriptor has the wrong item type",
        ));
    }
    Ok(StreamDescriptor::decode(item.canonical_bytes(), limits)?)
}

fn read_stream_descriptor_list(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> Result<Vec<StreamDescriptor>, AcceptedSetupPackageError> {
    let (count, payload) = read_list_header(item, CanonicalItemType::NestedTuple)?;
    if count > limits.maximum_item_count {
        return Err(AcceptedSetupPackageError::new(
            RefusalReason::OutsideSupportedProfile,
            "accepted setup package proof inventory exceeds the configured count limit",
        ));
    }
    let mut descriptors = Vec::with_capacity(count);
    let mut byte_offset = 0_usize;
    for _ in 0..count {
        let byte_length = encoded_tuple_byte_length(&payload[byte_offset..])?;
        let tuple_end = byte_offset.checked_add(byte_length).ok_or_else(|| {
            AcceptedSetupPackageError::new(
                RefusalReason::OutsideSupportedProfile,
                "accepted setup package proof inventory offset overflows",
            )
        })?;
        let descriptor_bytes = payload.get(byte_offset..tuple_end).ok_or_else(|| {
            AcceptedSetupPackageError::new(
                RefusalReason::MalformedEncoding,
                "accepted setup package proof descriptor is truncated",
            )
        })?;
        descriptors.push(StreamDescriptor::decode(descriptor_bytes, limits)?);
        byte_offset = tuple_end;
    }
    if byte_offset != payload.len() {
        return Err(AcceptedSetupPackageError::new(
            RefusalReason::MalformedEncoding,
            "accepted setup package proof inventory contains trailing bytes",
        ));
    }
    Ok(descriptors)
}

fn read_list_header(
    item: &CanonicalItem,
    expected_element_type: CanonicalItemType,
) -> Result<(usize, &[u8]), AcceptedSetupPackageError> {
    if item.item_type() != CanonicalItemType::HomogeneousList {
        return Err(AcceptedSetupPackageError::new(
            RefusalReason::WrongTypeOrLength,
            "accepted setup package list has the wrong item type",
        ));
    }
    let bytes = item.canonical_bytes();
    if bytes.len() < 6
        || u16::from_le_bytes([bytes[0], bytes[1]]) != expected_element_type.canonical_code()
    {
        return Err(AcceptedSetupPackageError::new(
            RefusalReason::WrongTypeOrLength,
            "accepted setup package list has the wrong element type",
        ));
    }
    let count = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    Ok((count, &bytes[6..]))
}

fn encoded_tuple_byte_length(bytes: &[u8]) -> Result<usize, AcceptedSetupPackageError> {
    if bytes.len() < 8 {
        return Err(AcceptedSetupPackageError::new(
            RefusalReason::MalformedEncoding,
            "accepted setup package proof descriptor tuple is truncated",
        ));
    }
    let item_count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let mut byte_offset = 8_usize;
    for _ in 0..item_count {
        let item_header_end = byte_offset.checked_add(6).ok_or_else(|| {
            AcceptedSetupPackageError::new(
                RefusalReason::OutsideSupportedProfile,
                "accepted setup package proof descriptor length overflows",
            )
        })?;
        let item_header = bytes.get(byte_offset..item_header_end).ok_or_else(|| {
            AcceptedSetupPackageError::new(
                RefusalReason::MalformedEncoding,
                "accepted setup package proof descriptor item header is truncated",
            )
        })?;
        let item_byte_length = u32::from_le_bytes([
            item_header[2],
            item_header[3],
            item_header[4],
            item_header[5],
        ]) as usize;
        byte_offset = item_header_end
            .checked_add(item_byte_length)
            .ok_or_else(|| {
                AcceptedSetupPackageError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "accepted setup package proof descriptor item length overflows",
                )
            })?;
        if byte_offset > bytes.len() {
            return Err(AcceptedSetupPackageError::new(
                RefusalReason::MalformedEncoding,
                "accepted setup package proof descriptor item is truncated",
            ));
        }
    }
    Ok(byte_offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected_public_proof_descriptor_count() -> usize {
        selected_accepted_setup_public_proof_slots()
            .expect("selected proof slots derive")
            .len()
    }

    fn test_hash(value: u8) -> Hash512 {
        Hash512::from_bytes([value; Hash512::BYTE_LENGTH])
    }

    fn test_descriptor(value: u8, total_byte_length: u64) -> StreamDescriptor {
        let chunk_count = total_byte_length.div_ceil(
            u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
                .expect("stream chunk byte length fits u64"),
        );
        StreamDescriptor::new(
            total_byte_length,
            (0..chunk_count)
                .map(|chunk_index| test_hash(value.wrapping_add(chunk_index as u8)))
                .collect(),
            test_hash(value.wrapping_add(0x40)),
        )
        .expect("test descriptor is valid")
    }

    fn hash_list(first_value: u8, count: usize) -> CanonicalItem {
        CanonicalItem::homogeneous_list(
            CanonicalItemType::Hash512,
            &(0..count)
                .map(|offset| CanonicalItem::hash512([first_value.wrapping_add(offset as u8); 64]))
                .collect::<Vec<_>>(),
        )
        .expect("test hash list encodes")
    }

    fn canonical_package_bytes(participant_count: usize, proof_descriptor_count: usize) -> Vec<u8> {
        let collective_public_key_descriptor = test_descriptor(0x10, 1_300_000);
        let evaluator_key_store_descriptor = test_descriptor(0x20, 2_100_000);
        let proof_descriptors = (0..proof_descriptor_count)
            .map(|proof_ordinal| {
                test_descriptor(
                    0x30_u8.wrapping_add(proof_ordinal as u8),
                    17_u64
                        .checked_add(
                            u64::try_from(proof_ordinal).expect("test proof ordinal fits u64"),
                        )
                        .expect("test descriptor length does not overflow"),
                )
            })
            .map(|descriptor| {
                CanonicalItem::from_canonical_bytes(
                    CanonicalItemType::NestedTuple,
                    descriptor.encode().expect("descriptor encodes"),
                    &CanonicalDecodeLimits::default(),
                )
                .expect("nested descriptor is canonical")
            })
            .collect::<Vec<_>>();
        CanonicalTuple::new(
            ACCEPTED_SETUP_PACKAGE_SCHEMA_IDENTIFIER,
            ACCEPTED_SETUP_PACKAGE_SCHEMA_VERSION,
            vec![
                hash_list(1, participant_count),
                hash_list(21, participant_count),
                hash_list(41, participant_count),
                hash_list(61, participant_count),
                hash_list(81, participant_count),
                CanonicalItem::from_canonical_bytes(
                    CanonicalItemType::NestedTuple,
                    collective_public_key_descriptor
                        .encode()
                        .expect("descriptor encodes"),
                    &CanonicalDecodeLimits::default(),
                )
                .expect("nested descriptor is canonical"),
                CanonicalItem::from_canonical_bytes(
                    CanonicalItemType::NestedTuple,
                    evaluator_key_store_descriptor
                        .encode()
                        .expect("descriptor encodes"),
                    &CanonicalDecodeLimits::default(),
                )
                .expect("nested descriptor is canonical"),
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &proof_descriptors)
                    .expect("proof descriptor list encodes"),
            ],
        )
        .encode()
        .expect("test package encodes")
    }

    #[test]
    fn canonical_package_decodes_exact_ordered_inventory_and_recomputes_hash() {
        let bytes = canonical_package_bytes(
            usize::from(FOUNDATION_PROFILE.participant_count),
            selected_public_proof_descriptor_count(),
        );
        let package =
            CanonicalAcceptedSetupPackage::decode(&bytes, &CanonicalDecodeLimits::default())
                .expect("canonical setup package decodes");
        assert_eq!(
            package.canonical_package_byte_length(),
            u64::try_from(bytes.len()).expect("package length fits u64")
        );
        assert_eq!(package.ordered_hash_list_carrier_byte_lengths(), [646; 5]);
        assert_eq!(package.setup_intent_object_hashes()[3], test_hash(4),);
        assert_eq!(
            package.public_randomness_commitment_object_hashes()[9],
            test_hash(30),
        );
        assert_eq!(
            package.public_randomness_reveal_object_hashes()[0],
            test_hash(41)
        );
        assert_eq!(
            package.dealer_public_record_object_hashes()[9],
            test_hash(70)
        );
        assert_eq!(
            package.private_share_acceptance_object_hashes()[4],
            test_hash(85)
        );
        assert_eq!(
            package.collective_public_key_descriptor().total_byte_length,
            1_300_000
        );
        assert_eq!(
            package.evaluator_key_store_descriptor().total_byte_length,
            2_100_000
        );
        assert_eq!(
            package.ordered_proof_descriptors().len(),
            selected_public_proof_descriptor_count()
        );
        assert_eq!(
            package.ordered_proof_descriptors()[52].total_byte_length,
            69
        );
        assert_eq!(
            package
                .ordered_proof_descriptor_total_byte_lengths()
                .collect::<Vec<_>>(),
            (17_u64..=69).collect::<Vec<_>>()
        );
        assert_eq!(
            package.setup_package_hash(),
            hash_foundation_tuple_512(
                ACCEPTED_SETUP_PACKAGE_HASH_DOMAIN,
                &[CanonicalItem::variable_bytes(&bytes).expect("package bytes frame")],
            )
            .expect("package hash derives"),
        );

        let selected_slots = selected_accepted_setup_public_proof_slots()
            .expect("selected setup proof slots derive");
        assert_eq!(
            selected_slots.len(),
            selected_public_proof_descriptor_count()
        );
        for (ordinal, schema_identifier, roster_position, schedule_position) in [
            (0, 0x1211, Some(0), None),
            (9, 0x1211, Some(9), None),
            (10, 0x1212, Some(0), None),
            (19, 0x1212, Some(9), None),
            (20, 0x1213, None, None),
            (21, 0x1214, Some(0), Some(0)),
            (30, 0x1214, Some(9), Some(0)),
            (31, 0x1215, None, Some(0)),
            (32, 0x1216, Some(0), Some(0)),
            (41, 0x1216, Some(9), Some(0)),
            (42, 0x1217, Some(0), Some(0)),
            (51, 0x1217, Some(9), Some(0)),
            (52, 0x1218, None, None),
        ] {
            let slot = selected_slots[ordinal];
            assert_eq!(
                slot.application_statement_schema_identifier,
                schema_identifier
            );
            assert_eq!(slot.roster_position, roster_position);
            assert_eq!(slot.schedule_position, schedule_position);
        }
    }

    #[test]
    fn canonical_package_refuses_wrong_roster_count_proof_count_and_descriptor_type() {
        let wrong_count = canonical_package_bytes(
            usize::from(FOUNDATION_PROFILE.participant_count).saturating_sub(1),
            selected_public_proof_descriptor_count(),
        );
        assert_eq!(
            CanonicalAcceptedSetupPackage::decode(&wrong_count, &CanonicalDecodeLimits::default(),)
                .expect_err("wrong roster count is refused")
                .refusal_reason,
            RefusalReason::WrongTypeOrLength,
        );

        for wrong_proof_count in [
            selected_public_proof_descriptor_count() - 1,
            selected_public_proof_descriptor_count() + 1,
        ] {
            let wrong_proof_inventory = canonical_package_bytes(
                usize::from(FOUNDATION_PROFILE.participant_count),
                wrong_proof_count,
            );
            assert_eq!(
                CanonicalAcceptedSetupPackage::decode(
                    &wrong_proof_inventory,
                    &CanonicalDecodeLimits::default(),
                )
                .expect_err("wrong selected proof count is refused")
                .refusal_reason,
                RefusalReason::WrongTypeOrLength,
            );
        }

        let valid = canonical_package_bytes(
            usize::from(FOUNDATION_PROFILE.participant_count),
            selected_public_proof_descriptor_count(),
        );
        let mut tuple = CanonicalTuple::decode(&valid, &CanonicalDecodeLimits::default())
            .expect("valid package tuple decodes");
        tuple.items[5] = CanonicalItem::hash512([0x5a; 64]);
        let wrong_descriptor_type = tuple.encode().expect("mutated package is canonical");
        assert_eq!(
            CanonicalAcceptedSetupPackage::decode(
                &wrong_descriptor_type,
                &CanonicalDecodeLimits::default(),
            )
            .expect_err("wrong descriptor type is refused")
            .refusal_reason,
            RefusalReason::WrongTypeOrLength,
        );
    }
}
