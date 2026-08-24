use std::collections::HashSet;

use super::canonical_tuple::CanonicalDecodeBudget;
use super::schemas::{
    BallotPackagePayload, SchemaResult, read_hash, read_hash_list, read_list_header, read_u64,
    read_variable_item, require_header,
};
use super::{
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE,
    FoundationObjectType, FoundationSchemaError, Hash512, ObjectEnvelope, ParticipantIdentity,
    RefusalReason, Roster, SignedCarrier, StreamDescriptor, hash_foundation_tuple_512,
};

pub const BALLOT_CANDIDATE_LIST_PAYLOAD_SCHEMA_IDENTIFIER: u16 = 0x1400;
pub const CANDIDATE_ENTRY_SCHEMA_IDENTIFIER: u16 = 0x1401;
pub const BALLOT_CANDIDATE_VIEW_SCHEMA_IDENTIFIER: u16 = 0x1402;
pub const CANDIDATE_LIST_INPUT_SCHEMA_IDENTIFIER: u16 = 0x1403;
pub const BALLOT_CANDIDATE_VIEW_INPUT_SCHEMA_IDENTIFIER: u16 = 0x1405;

const BALLOT_CANDIDATE_VIEW_ROOT_DOMAIN: &str =
    "sealed-lattice/aggregation/ballot-candidate-view/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateEntry {
    producer_sequence: u64,
    ballot_package_object_hash: Hash512,
}

impl CandidateEntry {
    pub fn new(producer_sequence: u64, ballot_package_object_hash: Hash512) -> Self {
        Self {
            producer_sequence,
            ballot_package_object_hash,
        }
    }

    pub const fn producer_sequence(self) -> u64 {
        self.producer_sequence
    }

    pub const fn ballot_package_object_hash(self) -> Hash512 {
        self.ballot_package_object_hash
    }

    fn canonical_tuple(self) -> CanonicalTuple {
        CanonicalTuple::new(
            CANDIDATE_ENTRY_SCHEMA_IDENTIFIER,
            1,
            vec![
                CanonicalItem::unsigned64(self.producer_sequence),
                CanonicalItem::hash512(self.ballot_package_object_hash.into_bytes()),
            ],
        )
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, CANDIDATE_ENTRY_SCHEMA_IDENTIFIER, 2)?;
        Ok(Self::new(
            read_u64(&tuple.items[0])?,
            read_hash(&tuple.items[1])?,
        ))
    }
}

/// Canonical payload of one roster-signed ballot candidate list. Entries are
/// consecutive because the sequence is the authenticated package slot, not a
/// caller-selected priority or wall-clock claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BallotCandidateListPayload {
    submission_cutoff_hash: Hash512,
    entries: Box<[CandidateEntry]>,
}

impl BallotCandidateListPayload {
    pub(crate) fn new(
        submission_cutoff_hash: Hash512,
        entries: Vec<CandidateEntry>,
    ) -> SchemaResult<Self> {
        validate_candidate_entries(&entries)?;
        Ok(Self {
            submission_cutoff_hash,
            entries: entries.into_boxed_slice(),
        })
    }

    pub(crate) const fn submission_cutoff_hash(&self) -> Hash512 {
        self.submission_cutoff_hash
    }

    pub(crate) fn entries(&self) -> &[CandidateEntry] {
        &self.entries
    }

    pub(crate) fn encode(&self) -> SchemaResult<Vec<u8>> {
        let entries = self
            .entries
            .iter()
            .copied()
            .map(|entry| CanonicalItem::nested_tuple(&entry.canonical_tuple()).map_err(Into::into))
            .collect::<SchemaResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            BALLOT_CANDIDATE_LIST_PAYLOAD_SCHEMA_IDENTIFIER,
            1,
            vec![
                CanonicalItem::hash512(self.submission_cutoff_hash.into_bytes()),
                CanonicalItem::homogeneous_list(CanonicalItemType::NestedTuple, &entries)?,
            ],
        )
        .encode()?)
    }

    pub(crate) fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        require_header(&tuple, BALLOT_CANDIDATE_LIST_PAYLOAD_SCHEMA_IDENTIFIER, 2)?;
        let entries = super::schemas::read_nested_tuple_list_with_budget(
            &tuple.items[1],
            limits,
            &mut budget,
        )?
        .iter()
        .map(CandidateEntry::from_tuple)
        .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(read_hash(&tuple.items[0])?, entries)
    }
}

fn validate_candidate_entries(entries: &[CandidateEntry]) -> SchemaResult<()> {
    if entries.is_empty() {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "ballot candidate list is empty",
        ));
    }
    for (entry_ordinal, entry) in entries.iter().enumerate() {
        let expected_sequence = u64::try_from(entry_ordinal).map_err(|_| {
            FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "candidate entry ordinal does not fit u64",
            )
        })?;
        if entry.producer_sequence != expected_sequence {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "candidate entries are not consecutive in producer-sequence order",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BallotCandidateView {
    candidate_list_object_hashes: Box<[Hash512]>,
}

impl BallotCandidateView {
    pub fn new(candidate_list_object_hashes: Vec<Hash512>) -> SchemaResult<Self> {
        if candidate_list_object_hashes.is_empty()
            || candidate_list_object_hashes.len()
                > usize::from(FOUNDATION_PROFILE.participant_count)
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "candidate view list count is outside the frozen-roster bound",
            ));
        }
        let mut distinct_hashes = HashSet::with_capacity(candidate_list_object_hashes.len());
        if candidate_list_object_hashes
            .iter()
            .any(|object_hash| !distinct_hashes.insert(*object_hash))
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::DuplicateIdentity,
                "candidate view repeats a candidate-list object",
            ));
        }
        Ok(Self {
            candidate_list_object_hashes: candidate_list_object_hashes.into_boxed_slice(),
        })
    }

    pub fn candidate_list_object_hashes(&self) -> &[Hash512] {
        &self.candidate_list_object_hashes
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        let hashes = self
            .candidate_list_object_hashes
            .iter()
            .map(|object_hash| CanonicalItem::hash512(object_hash.into_bytes()))
            .collect::<Vec<_>>();
        Ok(CanonicalTuple::new(
            BALLOT_CANDIDATE_VIEW_SCHEMA_IDENTIFIER,
            1,
            vec![CanonicalItem::homogeneous_list(
                CanonicalItemType::Hash512,
                &hashes,
            )?],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let tuple = CanonicalTuple::decode(bytes, limits)?;
        require_header(&tuple, BALLOT_CANDIDATE_VIEW_SCHEMA_IDENTIFIER, 1)?;
        Self::new(read_hash_list(&tuple.items[0])?)
    }

    pub fn candidate_view_root(&self, action_context_hash: Hash512) -> SchemaResult<Hash512> {
        Ok(hash_foundation_tuple_512(
            BALLOT_CANDIDATE_VIEW_ROOT_DOMAIN,
            &[
                CanonicalItem::hash512(action_context_hash.into_bytes()),
                CanonicalItem::variable_bytes(self.encode()?)?,
            ],
        )?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateListInput {
    canonical_signed_candidate_list_carrier: Box<[u8]>,
    canonical_signed_ballot_package_carriers: Box<[Box<[u8]>]>,
}

impl CandidateListInput {
    pub fn new(
        canonical_signed_candidate_list_carrier: Vec<u8>,
        canonical_signed_ballot_package_carriers: Vec<Vec<u8>>,
    ) -> SchemaResult<Self> {
        require_nonempty_bounded_carrier(&canonical_signed_candidate_list_carrier)?;
        if canonical_signed_ballot_package_carriers.is_empty() {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "candidate-list input has no ballot package carriers",
            ));
        }
        for carrier in &canonical_signed_ballot_package_carriers {
            require_nonempty_bounded_carrier(carrier)?;
        }
        Ok(Self {
            canonical_signed_candidate_list_carrier: canonical_signed_candidate_list_carrier
                .into_boxed_slice(),
            canonical_signed_ballot_package_carriers: canonical_signed_ballot_package_carriers
                .into_iter()
                .map(Vec::into_boxed_slice)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        })
    }

    pub fn canonical_signed_candidate_list_carrier(&self) -> &[u8] {
        &self.canonical_signed_candidate_list_carrier
    }

    pub fn canonical_signed_ballot_package_carriers(&self) -> &[Box<[u8]>] {
        &self.canonical_signed_ballot_package_carriers
    }

    fn canonical_tuple(&self) -> SchemaResult<CanonicalTuple> {
        let package_carriers = self
            .canonical_signed_ballot_package_carriers
            .iter()
            .map(CanonicalItem::variable_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CanonicalTuple::new(
            CANDIDATE_LIST_INPUT_SCHEMA_IDENTIFIER,
            1,
            vec![
                CanonicalItem::variable_bytes(&self.canonical_signed_candidate_list_carrier)?,
                CanonicalItem::homogeneous_list(CanonicalItemType::RawBytes, &package_carriers)?,
            ],
        ))
    }

    fn from_tuple(tuple: &CanonicalTuple) -> SchemaResult<Self> {
        require_header(tuple, CANDIDATE_LIST_INPUT_SCHEMA_IDENTIFIER, 2)?;
        Self::new(
            read_variable_item(&tuple.items[0], CanonicalItemType::RawBytes)?.to_vec(),
            read_variable_byte_list(&tuple.items[1])?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BallotCandidateViewInput {
    ordered_candidate_lists: Box<[CandidateListInput]>,
}

impl BallotCandidateViewInput {
    pub fn new(ordered_candidate_lists: Vec<CandidateListInput>) -> SchemaResult<Self> {
        if ordered_candidate_lists.is_empty()
            || ordered_candidate_lists.len() > usize::from(FOUNDATION_PROFILE.participant_count)
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "candidate-view input list count is outside the frozen-roster bound",
            ));
        }
        Ok(Self {
            ordered_candidate_lists: ordered_candidate_lists.into_boxed_slice(),
        })
    }

    pub fn ordered_candidate_lists(&self) -> &[CandidateListInput] {
        &self.ordered_candidate_lists
    }

    pub fn encode(&self) -> SchemaResult<Vec<u8>> {
        let lists = self
            .ordered_candidate_lists
            .iter()
            .map(|input| {
                input
                    .canonical_tuple()
                    .and_then(|tuple| CanonicalItem::nested_tuple(&tuple).map_err(Into::into))
            })
            .collect::<SchemaResult<Vec<_>>>()?;
        Ok(CanonicalTuple::new(
            BALLOT_CANDIDATE_VIEW_INPUT_SCHEMA_IDENTIFIER,
            1,
            vec![CanonicalItem::homogeneous_list(
                CanonicalItemType::NestedTuple,
                &lists,
            )?],
        )
        .encode()?)
    }

    pub fn decode(bytes: &[u8], limits: &CanonicalDecodeLimits) -> SchemaResult<Self> {
        let mut budget = CanonicalDecodeBudget::new(limits);
        let tuple = CanonicalTuple::decode_with_budget(bytes, limits, &mut budget)?;
        require_header(&tuple, BALLOT_CANDIDATE_VIEW_INPUT_SCHEMA_IDENTIFIER, 1)?;
        let inputs = super::schemas::read_nested_tuple_list_with_budget(
            &tuple.items[0],
            limits,
            &mut budget,
        )?
        .iter()
        .map(CandidateListInput::from_tuple)
        .collect::<SchemaResult<Vec<_>>>()?;
        Self::new(inputs)
    }
}

fn require_nonempty_bounded_carrier(carrier: &[u8]) -> SchemaResult<()> {
    if carrier.is_empty() {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "candidate transport carrier is empty",
        ));
    }
    if carrier.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "candidate transport carrier exceeds the copied-buffer bound",
        ));
    }
    Ok(())
}

fn read_variable_byte_list(item: &CanonicalItem) -> SchemaResult<Vec<Vec<u8>>> {
    let (count, bytes) = read_list_header(item, CanonicalItemType::RawBytes)?;
    let mut values = Vec::with_capacity(count);
    let mut offset = 0usize;
    for _ in 0..count {
        let length_end = offset.checked_add(4).ok_or_else(malformed_byte_list)?;
        let byte_length = u32::from_le_bytes(
            bytes
                .get(offset..length_end)
                .ok_or_else(malformed_byte_list)?
                .try_into()
                .map_err(|_| malformed_byte_list())?,
        );
        let value_end = length_end
            .checked_add(usize::try_from(byte_length).map_err(|_| malformed_byte_list())?)
            .ok_or_else(malformed_byte_list)?;
        values.push(
            bytes
                .get(length_end..value_end)
                .ok_or_else(malformed_byte_list)?
                .to_vec(),
        );
        offset = value_end;
    }
    if offset != bytes.len() {
        return Err(malformed_byte_list());
    }
    Ok(values)
}

fn malformed_byte_list() -> FoundationSchemaError {
    FoundationSchemaError::new(
        RefusalReason::MalformedEncoding,
        "candidate transport byte-list encoding is malformed",
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedBallotCandidatePackage {
    producer_sequence: u64,
    object_hash: Hash512,
    payload: BallotPackagePayload,
    complete_ballot_package_byte_length: u64,
    canonical_signed_carrier: Box<[u8]>,
}

impl AuthenticatedBallotCandidatePackage {
    pub const fn producer_sequence(&self) -> u64 {
        self.producer_sequence
    }

    pub const fn object_hash(&self) -> Hash512 {
        self.object_hash
    }

    pub const fn ciphertext_descriptor(&self) -> &StreamDescriptor {
        self.payload.ciphertext_descriptor()
    }

    pub const fn proof_descriptor(&self) -> &StreamDescriptor {
        self.payload.proof_descriptor()
    }

    pub const fn complete_ballot_package_byte_length(&self) -> u64 {
        self.complete_ballot_package_byte_length
    }

    pub fn canonical_signed_carrier(&self) -> &[u8] {
        &self.canonical_signed_carrier
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedBallotCandidateList {
    producer_roster_position: u16,
    producer_participant_identity: ParticipantIdentity,
    candidate_list_object_hash: Hash512,
    canonical_signed_candidate_list_carrier: Box<[u8]>,
    packages: Box<[AuthenticatedBallotCandidatePackage]>,
}

impl AuthenticatedBallotCandidateList {
    pub const fn producer_roster_position(&self) -> u16 {
        self.producer_roster_position
    }

    pub const fn producer_participant_identity(&self) -> ParticipantIdentity {
        self.producer_participant_identity
    }

    pub const fn candidate_list_object_hash(&self) -> Hash512 {
        self.candidate_list_object_hash
    }

    pub fn canonical_signed_candidate_list_carrier(&self) -> &[u8] {
        &self.canonical_signed_candidate_list_carrier
    }

    pub fn packages(&self) -> &[AuthenticatedBallotCandidatePackage] {
        &self.packages
    }
}

/// Structurally authenticated candidate transport. This does not claim that
/// any ballot proof is valid; each package remains subject to positive ballot
/// verification before selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedBallotCandidateView {
    semantic_view: BallotCandidateView,
    candidate_view_root: Hash512,
    submission_cutoff_hash: Hash512,
    setup_source_hash: Hash512,
    ordered_candidate_lists: Box<[AuthenticatedBallotCandidateList]>,
}

impl AuthenticatedBallotCandidateView {
    pub const fn candidate_view_root(&self) -> Hash512 {
        self.candidate_view_root
    }

    pub const fn submission_cutoff_hash(&self) -> Hash512 {
        self.submission_cutoff_hash
    }

    pub const fn setup_source_hash(&self) -> Hash512 {
        self.setup_source_hash
    }

    pub fn semantic_view(&self) -> &BallotCandidateView {
        &self.semantic_view
    }

    pub fn ordered_candidate_lists(&self) -> &[AuthenticatedBallotCandidateList] {
        &self.ordered_candidate_lists
    }
}

pub(crate) struct BallotCandidateAuthenticationContext<'context> {
    pub(crate) suite_identifier: Hash512,
    pub(crate) ceremony_context_hash: Hash512,
    pub(crate) action_context_hash: Hash512,
    pub(crate) submission_cutoff_hash: Hash512,
    pub(crate) roster: &'context Roster,
    pub(crate) maximum_ballot_attempts_per_participant: u64,
    pub(crate) maximum_candidate_packages_per_action: u32,
}

pub(crate) fn authenticate_ballot_candidate_view(
    input: &BallotCandidateViewInput,
    context: BallotCandidateAuthenticationContext<'_>,
) -> SchemaResult<AuthenticatedBallotCandidateView> {
    context.roster.validate()?;
    context.roster.require_selected_profile_size()?;
    let maximum_candidate_packages = usize::try_from(context.maximum_candidate_packages_per_action)
        .map_err(|_| {
            FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "candidate package limit does not fit this runtime",
            )
        })?;
    if context.maximum_ballot_attempts_per_participant == 0 || maximum_candidate_packages == 0 {
        return Err(FoundationSchemaError::new(
            RefusalReason::OutsideSupportedProfile,
            "candidate package limits are empty",
        ));
    }

    let roster_identities = context
        .roster
        .entries
        .iter()
        .map(|entry| entry.participant_identity())
        .collect::<SchemaResult<Vec<_>>>()?;
    let mut expected_setup_source_hash = None;
    let mut previous_roster_position = None;
    let mut total_package_count = 0usize;
    let mut package_object_hashes = HashSet::new();
    let mut authenticated_lists = Vec::with_capacity(input.ordered_candidate_lists.len());

    for list_input in input.ordered_candidate_lists.iter() {
        let candidate_list_carrier = decode_exact_signed_carrier(
            list_input.canonical_signed_candidate_list_carrier(),
            context.roster,
        )?;
        require_exact_envelope_context(
            &candidate_list_carrier.envelope,
            FoundationObjectType::BallotCandidateList,
            context.suite_identifier,
            context.ceremony_context_hash,
            context.action_context_hash,
        )?;
        if candidate_list_carrier.envelope.producer_sequence != 0
            || !candidate_list_carrier
                .envelope
                .ordered_prerequisite_hashes
                .is_empty()
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "candidate-list envelope has the wrong sequence or prerequisites",
            ));
        }
        let producer_identity = candidate_list_carrier
            .envelope
            .producer_participant_id
            .ok_or_else(|| {
                FoundationSchemaError::new(
                    RefusalReason::WrongTypeOrLength,
                    "candidate-list envelope has no producer",
                )
            })?;
        let producer_roster_position = roster_identities
            .iter()
            .position(|identity| *identity == producer_identity)
            .and_then(|position| u16::try_from(position).ok())
            .ok_or_else(|| {
                FoundationSchemaError::new(
                    RefusalReason::WrongContext,
                    "candidate-list producer is outside the frozen roster",
                )
            })?;
        if previous_roster_position.is_some_and(|previous| previous >= producer_roster_position) {
            return Err(FoundationSchemaError::new(
                RefusalReason::DuplicateIdentity,
                "candidate-list inputs are not in strictly increasing roster order",
            ));
        }
        previous_roster_position = Some(producer_roster_position);

        let payload = BallotCandidateListPayload::decode(
            &candidate_list_carrier.envelope.payload_bytes,
            &CanonicalDecodeLimits::default(),
        )?;
        if payload.encode()? != candidate_list_carrier.envelope.payload_bytes {
            return Err(FoundationSchemaError::new(
                RefusalReason::MalformedEncoding,
                "candidate-list payload is not encoded canonically",
            ));
        }
        if payload.submission_cutoff_hash() != context.submission_cutoff_hash {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongHashOrRoot,
                "candidate list does not bind the action submission cutoff",
            ));
        }
        if u64::try_from(payload.entries().len()).map_err(|_| {
            FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "candidate entry count does not fit u64",
            )
        })? > context.maximum_ballot_attempts_per_participant
            || payload.entries().len()
                != list_input.canonical_signed_ballot_package_carriers().len()
        {
            return Err(FoundationSchemaError::new(
                RefusalReason::WrongTypeOrLength,
                "candidate-list package count does not match the suite limit or payload",
            ));
        }
        total_package_count = total_package_count
            .checked_add(payload.entries().len())
            .ok_or_else(|| {
                FoundationSchemaError::new(
                    RefusalReason::OutsideSupportedProfile,
                    "candidate package count overflows",
                )
            })?;
        if total_package_count > maximum_candidate_packages {
            return Err(FoundationSchemaError::new(
                RefusalReason::OutsideSupportedProfile,
                "candidate package count exceeds the action bound",
            ));
        }

        let mut authenticated_packages = Vec::with_capacity(payload.entries().len());
        for (entry, canonical_package_carrier) in payload
            .entries()
            .iter()
            .zip(list_input.canonical_signed_ballot_package_carriers())
        {
            let package_carrier =
                decode_exact_signed_carrier(canonical_package_carrier, context.roster)?;
            require_exact_envelope_context(
                &package_carrier.envelope,
                FoundationObjectType::BallotPackage,
                context.suite_identifier,
                context.ceremony_context_hash,
                context.action_context_hash,
            )?;
            if package_carrier.envelope.producer_participant_id != Some(producer_identity)
                || package_carrier.envelope.producer_sequence != entry.producer_sequence()
            {
                return Err(FoundationSchemaError::new(
                    RefusalReason::WrongContext,
                    "candidate package has the wrong producer or sequence",
                ));
            }
            let [setup_source_hash] = <[Hash512; 1]>::try_from(
                package_carrier.envelope.ordered_prerequisite_hashes.clone(),
            )
            .map_err(|_| {
                FoundationSchemaError::new(
                    RefusalReason::WrongTypeOrLength,
                    "candidate package has the wrong prerequisite count",
                )
            })?;
            match expected_setup_source_hash {
                None => expected_setup_source_hash = Some(setup_source_hash),
                Some(expected) if expected != setup_source_hash => {
                    return Err(FoundationSchemaError::new(
                        RefusalReason::WrongHashOrRoot,
                        "candidate packages bind different setup sources",
                    ));
                }
                Some(_) => {}
            }
            let object_hash = package_carrier.envelope.object_hash()?;
            if object_hash != entry.ballot_package_object_hash()
                || !package_object_hashes.insert(object_hash)
            {
                return Err(FoundationSchemaError::new(
                    RefusalReason::WrongHashOrRoot,
                    "candidate package hash is wrong or duplicated",
                ));
            }
            let package_payload = BallotPackagePayload::decode(
                &package_carrier.envelope.payload_bytes,
                &CanonicalDecodeLimits::default(),
            )?;
            if package_payload.encode()? != package_carrier.envelope.payload_bytes {
                return Err(FoundationSchemaError::new(
                    RefusalReason::MalformedEncoding,
                    "candidate package payload is not encoded canonically",
                ));
            }
            let complete_ballot_package_byte_length =
                u64::try_from(canonical_package_carrier.len())
                    .ok()
                    .and_then(|length| {
                        length
                            .checked_add(package_payload.ciphertext_descriptor().total_byte_length)
                    })
                    .and_then(|length| {
                        length.checked_add(package_payload.proof_descriptor().total_byte_length)
                    })
                    .ok_or_else(|| {
                        FoundationSchemaError::new(
                            RefusalReason::OutsideSupportedProfile,
                            "complete ballot package byte length overflows",
                        )
                    })?;
            authenticated_packages.push(AuthenticatedBallotCandidatePackage {
                producer_sequence: entry.producer_sequence(),
                object_hash,
                payload: package_payload,
                complete_ballot_package_byte_length,
                canonical_signed_carrier: canonical_package_carrier.clone(),
            });
        }

        let candidate_list_object_hash = candidate_list_carrier.envelope.object_hash()?;
        authenticated_lists.push(AuthenticatedBallotCandidateList {
            producer_roster_position,
            producer_participant_identity: producer_identity,
            candidate_list_object_hash,
            canonical_signed_candidate_list_carrier: list_input
                .canonical_signed_candidate_list_carrier
                .clone(),
            packages: authenticated_packages.into_boxed_slice(),
        });
    }

    let semantic_view = BallotCandidateView::new(
        authenticated_lists
            .iter()
            .map(AuthenticatedBallotCandidateList::candidate_list_object_hash)
            .collect(),
    )?;
    let candidate_view_root = semantic_view.candidate_view_root(context.action_context_hash)?;
    Ok(AuthenticatedBallotCandidateView {
        semantic_view,
        candidate_view_root,
        submission_cutoff_hash: context.submission_cutoff_hash,
        setup_source_hash: expected_setup_source_hash.ok_or_else(|| {
            FoundationSchemaError::new(
                RefusalReason::MissingPrerequisite,
                "candidate view has no ballot setup-source binding",
            )
        })?,
        ordered_candidate_lists: authenticated_lists.into_boxed_slice(),
    })
}

fn decode_exact_signed_carrier(bytes: &[u8], roster: &Roster) -> SchemaResult<SignedCarrier> {
    require_nonempty_bounded_carrier(bytes)?;
    let carrier = SignedCarrier::decode(bytes, &CanonicalDecodeLimits::default())?;
    if carrier.encode()? != bytes {
        return Err(FoundationSchemaError::new(
            RefusalReason::MalformedEncoding,
            "candidate transport carrier is not encoded canonically",
        ));
    }
    carrier
        .verify_signature(roster)
        .into_result()
        .map_err(|reason| {
            FoundationSchemaError::new(reason, "candidate transport signature did not verify")
        })?;
    Ok(carrier)
}

fn require_exact_envelope_context(
    envelope: &ObjectEnvelope,
    expected_object_type: FoundationObjectType,
    suite_identifier: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
) -> SchemaResult<()> {
    if envelope.object_type != expected_object_type {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongTypeOrLength,
            "candidate transport object has the wrong family",
        ));
    }
    if envelope.suite_id != suite_identifier
        || envelope.ceremony_context_hash != ceremony_context_hash
        || envelope.action_context_hash != action_context_hash
    {
        return Err(FoundationSchemaError::new(
            RefusalReason::WrongContext,
            "candidate transport object has the wrong action context",
        ));
    }
    Ok(())
}
