use core::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::{
    encoding::{CanonicalReader, append_bytes, append_varuint},
    foundation::Hash512,
    hashing::hash_framed_parts_512,
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    replicated_random_sharing::{
        PSEUDORANDOM_SHARING_KEY_BYTE_LENGTH, ReplicatedRandomSharingGeometry,
        ReplicatedRandomSharingSubset,
    },
};

pub(crate) const REPLICATED_KEY_COMPONENT_BYTE_LENGTH: usize =
    PSEUDORANDOM_SHARING_KEY_BYTE_LENGTH as usize;
pub(crate) const REPLICATED_KEY_COMPONENT_COMMITMENT_BYTE_LENGTH: usize = 64;

pub(super) const REPLICATED_KEY_COORDINATE_MAGIC: &[u8] =
    b"sealed-lattice/replicated-key-coordinate";
pub(super) const REPLICATED_KEY_COMPONENT_COMMITMENT_MAGIC: &[u8] =
    b"sealed-lattice/replicated-key-component-commitment";
pub(super) const REPLICATED_KEY_COMPONENT_OPENING_MAGIC: &[u8] =
    b"sealed-lattice/replicated-key-component-opening";
pub(super) const REPLICATED_KEY_COMMITMENT_MANIFEST_MAGIC: &[u8] =
    b"sealed-lattice/replicated-key-commitment-manifest";
pub(super) const REPLICATED_KEY_DELIVERY_ACKNOWLEDGEMENT_MAGIC: &[u8] =
    b"sealed-lattice/replicated-key-delivery-acknowledgement";
pub(super) const REPLICATED_KEY_ARTIFACT_VERSION: u64 = 1;

pub(super) const REPLICATED_KEY_COMPONENT_COMMITMENT_DOMAIN: &str =
    "sealed-lattice/tally-preparation/replicated-key-component-commitment/v1";
pub(super) const REPLICATED_KEY_COMMITMENT_MANIFEST_DOMAIN: &str =
    "sealed-lattice/tally-preparation/replicated-key-commitment-manifest/v1";
pub(super) const REPLICATED_KEY_DELIVERY_ACKNOWLEDGEMENT_ROOT_DOMAIN: &str =
    "sealed-lattice/tally-preparation/replicated-key-delivery-acknowledgement-root/v1";

const RANDOM_SHARING_PURPOSE_CODE: u64 = 1;
const ZERO_SHARING_PURPOSE_CODE: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplicatedRandomSharingKeyPurpose {
    RandomSharing,
    DegreeDoubleZeroSharing { basis_position: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplicatedRandomSharingKeyCoordinate {
    context_identity: Hash512,
    participant_count: u16,
    excluded_position_mask: u32,
    purpose: ReplicatedRandomSharingKeyPurpose,
}

impl ReplicatedRandomSharingKeyCoordinate {
    pub(crate) fn new(
        context: TallyPreparationContext,
        subset: ReplicatedRandomSharingSubset,
        purpose: ReplicatedRandomSharingKeyPurpose,
    ) -> Result<Self, TallyPreparationError> {
        if context.participant_count() != subset.participant_count() {
            return Err(TallyPreparationError::ReplicatedKeyCoordinateMismatch);
        }
        validate_purpose(subset.active_fault_bound(), purpose)?;
        Ok(Self {
            context_identity: context.identity(),
            participant_count: subset.participant_count(),
            excluded_position_mask: subset.excluded_position_mask(),
            purpose,
        })
    }

    pub(crate) fn all(
        context: TallyPreparationContext,
    ) -> Result<Vec<Self>, TallyPreparationError> {
        let subsets = ReplicatedRandomSharingSubset::all(context.participant_count())?;
        let geometry = ReplicatedRandomSharingGeometry::derive(context.participant_count())?;
        let mut coordinates = Vec::with_capacity(
            usize::try_from(geometry.total_key_count)
                .map_err(|_| TallyPreparationError::IntegerConversion)?,
        );
        for subset in subsets {
            coordinates.push(Self::new(
                context,
                subset,
                ReplicatedRandomSharingKeyPurpose::RandomSharing,
            )?);
            for basis_position in 0..subset.active_fault_bound() {
                coordinates.push(Self::new(
                    context,
                    subset,
                    ReplicatedRandomSharingKeyPurpose::DegreeDoubleZeroSharing { basis_position },
                )?);
            }
        }
        if coordinates.len()
            != usize::try_from(geometry.total_key_count)
                .map_err(|_| TallyPreparationError::IntegerConversion)?
        {
            return Err(TallyPreparationError::ReplicatedKeyInventoryMismatch);
        }
        Ok(coordinates)
    }

    pub(crate) const fn context_identity(self) -> Hash512 {
        self.context_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn excluded_position_mask(self) -> u32 {
        self.excluded_position_mask
    }

    pub(crate) const fn purpose(self) -> ReplicatedRandomSharingKeyPurpose {
        self.purpose
    }

    pub(crate) fn member_positions(self) -> Result<Vec<u16>, TallyPreparationError> {
        Ok(self.subset()?.member_positions())
    }

    pub(crate) fn contains(self, roster_position: u16) -> Result<bool, TallyPreparationError> {
        self.subset()?.contains(roster_position)
    }

    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, REPLICATED_KEY_COORDINATE_MAGIC);
        append_varuint(&mut bytes, REPLICATED_KEY_ARTIFACT_VERSION);
        append_bytes(&mut bytes, self.context_identity.as_bytes());
        append_varuint(&mut bytes, u64::from(self.participant_count));
        append_varuint(&mut bytes, u64::from(self.excluded_position_mask));
        match self.purpose {
            ReplicatedRandomSharingKeyPurpose::RandomSharing => {
                append_varuint(&mut bytes, RANDOM_SHARING_PURPOSE_CODE);
            }
            ReplicatedRandomSharingKeyPurpose::DegreeDoubleZeroSharing { basis_position } => {
                append_varuint(&mut bytes, ZERO_SHARING_PURPOSE_CODE);
                append_varuint(&mut bytes, u64::from(basis_position));
            }
        }
        bytes
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let mut reader = CanonicalReader::new(bytes);
        read_magic(&mut reader, REPLICATED_KEY_COORDINATE_MAGIC, "coordinate")?;
        read_artifact_version(&mut reader, "coordinate")?;
        let context_identity = read_hash512(&mut reader, "context identity")?;
        let participant_count = read_u16(&mut reader)?;
        let excluded_position_mask = read_u32(&mut reader)?;
        let purpose_code = reader.read_varuint()?;
        let purpose = match purpose_code {
            RANDOM_SHARING_PURPOSE_CODE => ReplicatedRandomSharingKeyPurpose::RandomSharing,
            ZERO_SHARING_PURPOSE_CODE => {
                ReplicatedRandomSharingKeyPurpose::DegreeDoubleZeroSharing {
                    basis_position: read_u16(&mut reader)?,
                }
            }
            _ => return Err(TallyPreparationError::ReplicatedKeyPurposeOutOfRange),
        };
        require_finished(&reader, "coordinate")?;

        let coordinate = Self {
            context_identity,
            participant_count,
            excluded_position_mask,
            purpose,
        };
        let subset = coordinate.subset()?;
        validate_purpose(subset.active_fault_bound(), purpose)?;
        Ok(coordinate)
    }

    fn subset(self) -> Result<ReplicatedRandomSharingSubset, TallyPreparationError> {
        let mask_limit = 1_u32
            .checked_shl(u32::from(self.participant_count))
            .ok_or(TallyPreparationError::ReplicatedKeyCoordinateMismatch)?;
        if self.excluded_position_mask >= mask_limit {
            return Err(TallyPreparationError::ReplicatedKeyCoordinateMismatch);
        }
        let excluded_positions = (0..self.participant_count)
            .filter(|roster_position| {
                let position_bit = 1_u32 << u32::from(*roster_position);
                self.excluded_position_mask & position_bit != 0
            })
            .collect::<Vec<_>>();
        ReplicatedRandomSharingSubset::from_excluded_positions(
            self.participant_count,
            &excluded_positions,
        )
        .map_err(|_| TallyPreparationError::ReplicatedKeyCoordinateMismatch)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplicatedKeyComponentCommitment {
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    contributor_position: u16,
    digest: [u8; REPLICATED_KEY_COMPONENT_COMMITMENT_BYTE_LENGTH],
}

impl ReplicatedKeyComponentCommitment {
    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, REPLICATED_KEY_COMPONENT_COMMITMENT_MAGIC);
        append_varuint(&mut bytes, REPLICATED_KEY_ARTIFACT_VERSION);
        append_bytes(&mut bytes, &self.coordinate.canonical_bytes());
        append_varuint(&mut bytes, u64::from(self.contributor_position));
        append_bytes(&mut bytes, &self.digest);
        bytes
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let mut reader = CanonicalReader::new(bytes);
        read_magic(
            &mut reader,
            REPLICATED_KEY_COMPONENT_COMMITMENT_MAGIC,
            "component commitment",
        )?;
        read_artifact_version(&mut reader, "component commitment")?;
        let coordinate =
            ReplicatedRandomSharingKeyCoordinate::from_canonical_bytes(&reader.read_bytes()?)?;
        let contributor_position = read_u16(&mut reader)?;
        validate_contributor(coordinate, contributor_position)?;
        let digest = read_fixed_bytes::<REPLICATED_KEY_COMPONENT_COMMITMENT_BYTE_LENGTH>(
            &mut reader,
            "component commitment digest",
        )?;
        require_finished(&reader, "component commitment")?;
        Ok(Self {
            coordinate,
            contributor_position,
            digest,
        })
    }
}

impl fmt::Debug for ReplicatedKeyComponentCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicatedKeyComponentCommitment")
            .field("coordinate", &self.coordinate)
            .field("contributor_position", &self.contributor_position)
            .field("digest", &"[digest]")
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct ReplicatedKeyComponentOpening {
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    contributor_position: u16,
    component: [u8; REPLICATED_KEY_COMPONENT_BYTE_LENGTH],
}

impl ReplicatedKeyComponentOpening {
    pub(crate) fn canonical_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, REPLICATED_KEY_COMPONENT_OPENING_MAGIC);
        append_varuint(&mut bytes, REPLICATED_KEY_ARTIFACT_VERSION);
        append_bytes(&mut bytes, &self.coordinate.canonical_bytes());
        append_varuint(&mut bytes, u64::from(self.contributor_position));
        append_bytes(&mut bytes, &self.component);
        Zeroizing::new(bytes)
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let mut reader = CanonicalReader::new(bytes);
        read_magic(
            &mut reader,
            REPLICATED_KEY_COMPONENT_OPENING_MAGIC,
            "component opening",
        )?;
        read_artifact_version(&mut reader, "component opening")?;
        let coordinate =
            ReplicatedRandomSharingKeyCoordinate::from_canonical_bytes(&reader.read_bytes()?)?;
        let contributor_position = read_u16(&mut reader)?;
        validate_contributor(coordinate, contributor_position)?;
        let component =
            read_fixed_bytes::<REPLICATED_KEY_COMPONENT_BYTE_LENGTH>(&mut reader, "key component")?;
        require_finished(&reader, "component opening")?;
        Ok(Self {
            coordinate,
            contributor_position,
            component,
        })
    }
}

impl fmt::Debug for ReplicatedKeyComponentOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicatedKeyComponentOpening")
            .field("coordinate", &self.coordinate)
            .field("contributor_position", &self.contributor_position)
            .field("component", &"[redacted]")
            .finish()
    }
}

impl Drop for ReplicatedKeyComponentOpening {
    fn drop(&mut self) {
        self.component.zeroize();
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct ReplicatedRandomSharingKey {
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    bytes: [u8; REPLICATED_KEY_COMPONENT_BYTE_LENGTH],
}

impl ReplicatedRandomSharingKey {
    pub(crate) const fn coordinate(&self) -> ReplicatedRandomSharingKeyCoordinate {
        self.coordinate
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; REPLICATED_KEY_COMPONENT_BYTE_LENGTH] {
        &self.bytes
    }
}

impl fmt::Debug for ReplicatedRandomSharingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReplicatedRandomSharingKey([redacted])")
    }
}

impl Drop for ReplicatedRandomSharingKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplicatedKeyCommitmentManifest {
    context_identity: Hash512,
    participant_count: u16,
    commitment_count: u64,
    root: Hash512,
}

impl ReplicatedKeyCommitmentManifest {
    pub(crate) const fn context_identity(self) -> Hash512 {
        self.context_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn commitment_count(self) -> u64 {
        self.commitment_count
    }

    pub(crate) const fn root(self) -> Hash512 {
        self.root
    }

    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, REPLICATED_KEY_COMMITMENT_MANIFEST_MAGIC);
        append_varuint(&mut bytes, REPLICATED_KEY_ARTIFACT_VERSION);
        append_bytes(&mut bytes, self.context_identity.as_bytes());
        append_varuint(&mut bytes, u64::from(self.participant_count));
        append_varuint(&mut bytes, self.commitment_count);
        append_bytes(&mut bytes, self.root.as_bytes());
        bytes
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let mut reader = CanonicalReader::new(bytes);
        read_magic(
            &mut reader,
            REPLICATED_KEY_COMMITMENT_MANIFEST_MAGIC,
            "commitment manifest",
        )?;
        read_artifact_version(&mut reader, "commitment manifest")?;
        let context_identity = read_hash512(&mut reader, "context identity")?;
        let participant_count = read_u16(&mut reader)?;
        let commitment_count = reader.read_varuint()?;
        let root = read_hash512(&mut reader, "commitment manifest root")?;
        require_finished(&reader, "commitment manifest")?;

        let geometry = ReplicatedRandomSharingGeometry::derive(participant_count)?;
        let expected_commitment_count =
            checked_multiply(geometry.total_key_count, geometry.authorized_subset_size)?;
        if commitment_count != expected_commitment_count {
            return Err(TallyPreparationError::ReplicatedKeyInventoryMismatch);
        }
        Ok(Self {
            context_identity,
            participant_count,
            commitment_count,
            root,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplicatedKeyDeliveryAcknowledgement {
    context_identity: Hash512,
    participant_count: u16,
    recipient_position: u16,
    commitment_manifest_root: Hash512,
    expected_delivery_count: u64,
}

impl ReplicatedKeyDeliveryAcknowledgement {
    pub(crate) const fn recipient_position(self) -> u16 {
        self.recipient_position
    }

    pub(crate) const fn expected_delivery_count(self) -> u64 {
        self.expected_delivery_count
    }

    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, REPLICATED_KEY_DELIVERY_ACKNOWLEDGEMENT_MAGIC);
        append_varuint(&mut bytes, REPLICATED_KEY_ARTIFACT_VERSION);
        append_bytes(&mut bytes, self.context_identity.as_bytes());
        append_varuint(&mut bytes, u64::from(self.participant_count));
        append_varuint(&mut bytes, u64::from(self.recipient_position));
        append_bytes(&mut bytes, self.commitment_manifest_root.as_bytes());
        append_varuint(&mut bytes, self.expected_delivery_count);
        bytes
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TallyPreparationError> {
        let mut reader = CanonicalReader::new(bytes);
        read_magic(
            &mut reader,
            REPLICATED_KEY_DELIVERY_ACKNOWLEDGEMENT_MAGIC,
            "delivery acknowledgement",
        )?;
        read_artifact_version(&mut reader, "delivery acknowledgement")?;
        let context_identity = read_hash512(&mut reader, "context identity")?;
        let participant_count = read_u16(&mut reader)?;
        let recipient_position = read_u16(&mut reader)?;
        let commitment_manifest_root = read_hash512(&mut reader, "commitment manifest root")?;
        let expected_delivery_count = reader.read_varuint()?;
        require_finished(&reader, "delivery acknowledgement")?;

        let geometry = ReplicatedRandomSharingGeometry::derive(participant_count)?;
        if recipient_position >= participant_count
            || expected_delivery_count != delivery_count_per_participant(geometry)?
        {
            return Err(TallyPreparationError::ReplicatedKeyAcknowledgementMismatch);
        }
        Ok(Self {
            context_identity,
            participant_count,
            recipient_position,
            commitment_manifest_root,
            expected_delivery_count,
        })
    }
}

pub(crate) fn create_replicated_key_component(
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    contributor_position: u16,
    component: [u8; REPLICATED_KEY_COMPONENT_BYTE_LENGTH],
) -> Result<
    (
        ReplicatedKeyComponentCommitment,
        ReplicatedKeyComponentOpening,
    ),
    TallyPreparationError,
> {
    validate_contributor(coordinate, contributor_position)?;
    let digest = derive_component_commitment_digest(coordinate, contributor_position, &component);
    Ok((
        ReplicatedKeyComponentCommitment {
            coordinate,
            contributor_position,
            digest,
        },
        ReplicatedKeyComponentOpening {
            coordinate,
            contributor_position,
            component,
        },
    ))
}

pub(crate) fn verify_replicated_key_component(
    expected_coordinate: ReplicatedRandomSharingKeyCoordinate,
    expected_contributor_position: u16,
    commitment: ReplicatedKeyComponentCommitment,
    opening: &ReplicatedKeyComponentOpening,
) -> Result<(), TallyPreparationError> {
    validate_contributor(expected_coordinate, expected_contributor_position)?;
    if commitment.coordinate != expected_coordinate
        || opening.coordinate != expected_coordinate
        || commitment.contributor_position != expected_contributor_position
        || opening.contributor_position != expected_contributor_position
    {
        return Err(TallyPreparationError::ReplicatedKeyCoordinateMismatch);
    }
    let actual_digest = derive_component_commitment_digest(
        expected_coordinate,
        expected_contributor_position,
        &opening.component,
    );
    if commitment.digest != actual_digest {
        return Err(TallyPreparationError::ReplicatedKeyCommitmentMismatch);
    }
    Ok(())
}

pub(crate) fn validate_replicated_key_delivery_recipient(
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    contributor_position: u16,
    recipient_position: u16,
) -> Result<(), TallyPreparationError> {
    validate_contributor(coordinate, contributor_position)?;
    if recipient_position == contributor_position {
        return Err(TallyPreparationError::ReplicatedKeySelfDelivery);
    }
    if !coordinate.contains(recipient_position)? {
        return Err(TallyPreparationError::ReplicatedKeyRecipientNotMember { recipient_position });
    }
    Ok(())
}

pub(crate) fn combine_replicated_random_sharing_key(
    expected_coordinate: ReplicatedRandomSharingKeyCoordinate,
    commitments: &[ReplicatedKeyComponentCommitment],
    openings: &[ReplicatedKeyComponentOpening],
) -> Result<ReplicatedRandomSharingKey, TallyPreparationError> {
    let expected_contributors = expected_coordinate.member_positions()?;
    if commitments.len() != expected_contributors.len()
        || openings.len() != expected_contributors.len()
    {
        return Err(TallyPreparationError::ReplicatedKeyInventoryMismatch);
    }

    let mut combined_key = [0_u8; REPLICATED_KEY_COMPONENT_BYTE_LENGTH];
    for ((expected_contributor, commitment), opening) in
        expected_contributors.iter().zip(commitments).zip(openings)
    {
        verify_replicated_key_component(
            expected_coordinate,
            *expected_contributor,
            *commitment,
            opening,
        )?;
        for (combined_byte, component_byte) in combined_key.iter_mut().zip(opening.component.iter())
        {
            *combined_byte ^= component_byte;
        }
    }
    Ok(ReplicatedRandomSharingKey {
        coordinate: expected_coordinate,
        bytes: combined_key,
    })
}

pub(crate) fn expected_replicated_key_component_slots(
    context: TallyPreparationContext,
) -> Result<Vec<(ReplicatedRandomSharingKeyCoordinate, u16)>, TallyPreparationError> {
    let geometry = ReplicatedRandomSharingGeometry::derive(context.participant_count())?;
    let expected_slot_count =
        checked_multiply(geometry.total_key_count, geometry.authorized_subset_size)?;
    let mut slots = Vec::with_capacity(
        usize::try_from(expected_slot_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?,
    );
    for coordinate in ReplicatedRandomSharingKeyCoordinate::all(context)? {
        for contributor_position in coordinate.member_positions()? {
            slots.push((coordinate, contributor_position));
        }
    }
    if slots.len()
        != usize::try_from(expected_slot_count)
            .map_err(|_| TallyPreparationError::IntegerConversion)?
    {
        return Err(TallyPreparationError::ReplicatedKeyInventoryMismatch);
    }
    Ok(slots)
}

pub(crate) fn derive_replicated_key_commitment_manifest(
    context: TallyPreparationContext,
    commitments: &[ReplicatedKeyComponentCommitment],
) -> Result<ReplicatedKeyCommitmentManifest, TallyPreparationError> {
    let expected_slots = expected_replicated_key_component_slots(context)?;
    if commitments.len() != expected_slots.len() {
        return Err(TallyPreparationError::ReplicatedKeyInventoryMismatch);
    }

    let mut manifest_payload = Vec::new();
    append_varuint(
        &mut manifest_payload,
        u64::try_from(commitments.len()).map_err(|_| TallyPreparationError::IntegerConversion)?,
    );
    for ((expected_coordinate, expected_contributor), commitment) in
        expected_slots.iter().zip(commitments)
    {
        if commitment.coordinate != *expected_coordinate
            || commitment.contributor_position != *expected_contributor
        {
            return Err(TallyPreparationError::ReplicatedKeyInventoryMismatch);
        }
        append_bytes(&mut manifest_payload, &commitment.canonical_bytes());
    }
    let root = Hash512::from_bytes(hash_framed_parts_512(
        REPLICATED_KEY_COMMITMENT_MANIFEST_DOMAIN,
        &[context.identity().as_bytes(), &manifest_payload],
    ));
    Ok(ReplicatedKeyCommitmentManifest {
        context_identity: context.identity(),
        participant_count: context.participant_count(),
        commitment_count: u64::try_from(commitments.len())
            .map_err(|_| TallyPreparationError::IntegerConversion)?,
        root,
    })
}

pub(crate) fn create_replicated_key_delivery_acknowledgement(
    context: TallyPreparationContext,
    manifest: ReplicatedKeyCommitmentManifest,
    recipient_position: u16,
) -> Result<ReplicatedKeyDeliveryAcknowledgement, TallyPreparationError> {
    if manifest.context_identity != context.identity()
        || manifest.participant_count != context.participant_count()
        || recipient_position >= context.participant_count()
    {
        return Err(TallyPreparationError::ReplicatedKeyAcknowledgementMismatch);
    }
    let geometry = ReplicatedRandomSharingGeometry::derive(context.participant_count())?;
    Ok(ReplicatedKeyDeliveryAcknowledgement {
        context_identity: context.identity(),
        participant_count: context.participant_count(),
        recipient_position,
        commitment_manifest_root: manifest.root,
        expected_delivery_count: delivery_count_per_participant(geometry)?,
    })
}

pub(crate) fn derive_replicated_key_delivery_acknowledgement_root(
    context: TallyPreparationContext,
    manifest: ReplicatedKeyCommitmentManifest,
    acknowledgements: &[ReplicatedKeyDeliveryAcknowledgement],
) -> Result<Hash512, TallyPreparationError> {
    if manifest.context_identity != context.identity()
        || manifest.participant_count != context.participant_count()
        || acknowledgements.len() != usize::from(context.participant_count())
    {
        return Err(TallyPreparationError::ReplicatedKeyAcknowledgementMismatch);
    }
    let geometry = ReplicatedRandomSharingGeometry::derive(context.participant_count())?;
    let expected_delivery_count = delivery_count_per_participant(geometry)?;
    let mut acknowledgement_payload = Vec::new();
    append_varuint(
        &mut acknowledgement_payload,
        u64::try_from(acknowledgements.len())
            .map_err(|_| TallyPreparationError::IntegerConversion)?,
    );
    for (recipient_position, acknowledgement) in acknowledgements.iter().enumerate() {
        if acknowledgement.context_identity != context.identity()
            || acknowledgement.participant_count != context.participant_count()
            || acknowledgement.recipient_position
                != u16::try_from(recipient_position)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?
            || acknowledgement.commitment_manifest_root != manifest.root
            || acknowledgement.expected_delivery_count != expected_delivery_count
        {
            return Err(TallyPreparationError::ReplicatedKeyAcknowledgementMismatch);
        }
        append_bytes(
            &mut acknowledgement_payload,
            &acknowledgement.canonical_bytes(),
        );
    }
    Ok(Hash512::from_bytes(hash_framed_parts_512(
        REPLICATED_KEY_DELIVERY_ACKNOWLEDGEMENT_ROOT_DOMAIN,
        &[
            context.identity().as_bytes(),
            &manifest.canonical_bytes(),
            &acknowledgement_payload,
        ],
    )))
}

fn derive_component_commitment_digest(
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    contributor_position: u16,
    component: &[u8; REPLICATED_KEY_COMPONENT_BYTE_LENGTH],
) -> [u8; REPLICATED_KEY_COMPONENT_COMMITMENT_BYTE_LENGTH] {
    let mut contributor_bytes = Vec::new();
    append_varuint(&mut contributor_bytes, u64::from(contributor_position));
    hash_framed_parts_512(
        REPLICATED_KEY_COMPONENT_COMMITMENT_DOMAIN,
        &[&coordinate.canonical_bytes(), &contributor_bytes, component],
    )
}

fn validate_purpose(
    active_fault_bound: u16,
    purpose: ReplicatedRandomSharingKeyPurpose,
) -> Result<(), TallyPreparationError> {
    if let ReplicatedRandomSharingKeyPurpose::DegreeDoubleZeroSharing { basis_position } = purpose
        && basis_position >= active_fault_bound
    {
        return Err(TallyPreparationError::ReplicatedKeyPurposeOutOfRange);
    }
    Ok(())
}

fn validate_contributor(
    coordinate: ReplicatedRandomSharingKeyCoordinate,
    contributor_position: u16,
) -> Result<(), TallyPreparationError> {
    if !coordinate.contains(contributor_position)? {
        return Err(TallyPreparationError::ReplicatedKeyContributorNotMember {
            contributor_position,
        });
    }
    Ok(())
}

fn delivery_count_per_participant(
    geometry: ReplicatedRandomSharingGeometry,
) -> Result<u64, TallyPreparationError> {
    checked_multiply(
        geometry.key_count_per_participant,
        geometry
            .authorized_subset_size
            .checked_sub(1)
            .ok_or(TallyPreparationError::GeometryMismatch)?,
    )
}

fn read_magic(
    reader: &mut CanonicalReader<'_>,
    expected_magic: &[u8],
    artifact: &'static str,
) -> Result<(), TallyPreparationError> {
    if reader.read_bytes()?.as_slice() != expected_magic {
        return Err(TallyPreparationError::ReplicatedKeyArtifactMagicMismatch { artifact });
    }
    Ok(())
}

fn read_artifact_version(
    reader: &mut CanonicalReader<'_>,
    artifact: &'static str,
) -> Result<(), TallyPreparationError> {
    let version = reader.read_varuint()?;
    if version != REPLICATED_KEY_ARTIFACT_VERSION {
        return Err(
            TallyPreparationError::UnsupportedReplicatedKeyArtifactVersion { artifact, version },
        );
    }
    Ok(())
}

fn read_hash512(
    reader: &mut CanonicalReader<'_>,
    field: &'static str,
) -> Result<Hash512, TallyPreparationError> {
    Ok(Hash512::from_bytes(read_fixed_bytes::<64>(reader, field)?))
}

fn read_fixed_bytes<const BYTE_LENGTH: usize>(
    reader: &mut CanonicalReader<'_>,
    field: &'static str,
) -> Result<[u8; BYTE_LENGTH], TallyPreparationError> {
    let bytes = reader.read_bytes()?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| TallyPreparationError::ReplicatedKeyFieldByteLength {
            field,
            expected: BYTE_LENGTH,
            actual: bytes.len(),
        })
}

fn read_u16(reader: &mut CanonicalReader<'_>) -> Result<u16, TallyPreparationError> {
    u16::try_from(reader.read_varuint()?).map_err(|_| TallyPreparationError::IntegerConversion)
}

fn read_u32(reader: &mut CanonicalReader<'_>) -> Result<u32, TallyPreparationError> {
    u32::try_from(reader.read_varuint()?).map_err(|_| TallyPreparationError::IntegerConversion)
}

fn require_finished(
    reader: &CanonicalReader<'_>,
    artifact: &'static str,
) -> Result<(), TallyPreparationError> {
    if !reader.is_finished() {
        return Err(TallyPreparationError::TrailingReplicatedKeyArtifactBytes { artifact });
    }
    Ok(())
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}
