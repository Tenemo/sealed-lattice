use core::fmt;

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512,
    hash_foundation_tuple_512,
};

use super::{
    TallyPreparationError,
    pseudorandom_zero_sharing_pair_and_coin_seed_320::{
        CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH,
        SeedCatalogSecretLeafError320,
        verify_pseudorandom_zero_sharing_pair_seed_opening_catalog_inclusion_320,
    },
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogCoordinate320,
        PseudorandomZeroSharingSeedCatalogInclusionProof320,
        PseudorandomZeroSharingSeedCatalogLayout320,
    },
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320::{
        PseudorandomZeroSharingSeedCatalogRootInventoryError,
        VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
    },
    pseudorandom_zero_sharing_subset_seed_320::{
        CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH,
    },
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const DELIVERY_DESCRIPTOR_ITEM_COUNT: usize = 9;
const RECIPIENT_INVENTORY_ITEM_COUNT: usize = 7;
const MAXIMUM_DELIVERY_CONTROL_OBJECT_BYTE_LENGTH: usize = 4_096;
const MAXIMUM_DELIVERY_CONTROL_OBJECT_ITEM_BYTE_LENGTH: usize = 512;
const MAXIMUM_DELIVERY_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 16_384;
const CANONICAL_TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const CANONICAL_ITEM_HEADER_BYTE_LENGTH: usize = 6;
const CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH: usize = 4;

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-delivery-descriptor";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-delivery-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-recipient-inventory";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-recipient-inventory-identity";

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_BODY_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + DELIVERY_DESCRIPTOR_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_DOMAIN.len()
        + 3 * Hash512::BYTE_LENGTH
        + 4 * size_of::<u16>()
        + size_of::<u64>();
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_BODY_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + RECIPIENT_INVENTORY_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_DOMAIN.len()
        + 3 * Hash512::BYTE_LENGTH
        + 3 * size_of::<u16>();

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedDeliveryError320 {
    Canonical(CanonicalCodecError),
    Preparation(TallyPreparationError),
    RootInventory(PseudorandomZeroSharingSeedCatalogRootInventoryError),
    SecretLeaf(SeedCatalogSecretLeafError320),
    EndpointMismatch {
        sender_position: u16,
        recipient_position: u16,
        participant_count: u16,
    },
    DescriptorMismatch {
        field: &'static str,
    },
    MissingSenderRoot {
        sender_position: u16,
    },
    DeliveryEntryCount {
        expected: usize,
        actual: usize,
    },
    DeliveryCount {
        expected: usize,
        actual: usize,
    },
    DeliveryOrder {
        delivery_index: usize,
        expected_sender_position: u16,
        actual_sender_position: u16,
    },
    IntegerConversion,
    ArithmeticOverflow,
}

impl From<CanonicalCodecError> for PseudorandomZeroSharingSeedDeliveryError320 {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<TallyPreparationError> for PseudorandomZeroSharingSeedDeliveryError320 {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl From<PseudorandomZeroSharingSeedCatalogRootInventoryError>
    for PseudorandomZeroSharingSeedDeliveryError320
{
    fn from(error: PseudorandomZeroSharingSeedCatalogRootInventoryError) -> Self {
        Self::RootInventory(error)
    }
}

impl From<SeedCatalogSecretLeafError320> for PseudorandomZeroSharingSeedDeliveryError320 {
    fn from(error: SeedCatalogSecretLeafError320) -> Self {
        Self::SecretLeaf(error)
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedDeliveryError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => write!(formatter, "canonical seed-delivery error: {error}"),
            Self::Preparation(error) => {
                write!(formatter, "seed-delivery preparation error: {error}")
            }
            Self::RootInventory(error) => {
                write!(formatter, "seed-delivery root-inventory error: {error}")
            }
            Self::SecretLeaf(error) => {
                write!(formatter, "seed-delivery secret-leaf error: {error}")
            }
            Self::EndpointMismatch {
                sender_position,
                recipient_position,
                participant_count,
            } => write!(
                formatter,
                "seed delivery from participant {sender_position} to participant {recipient_position} is invalid for a {participant_count}-participant roster"
            ),
            Self::DescriptorMismatch { field } => {
                write!(formatter, "seed-delivery descriptor has a wrong {field}")
            }
            Self::MissingSenderRoot { sender_position } => write!(
                formatter,
                "seed-delivery root inventory has no root for sender {sender_position}"
            ),
            Self::DeliveryEntryCount { expected, actual } => write!(
                formatter,
                "seed-delivery payload has {actual} entries; expected {expected}"
            ),
            Self::DeliveryCount { expected, actual } => write!(
                formatter,
                "seed-recipient inventory has {actual} deliveries; expected {expected}"
            ),
            Self::DeliveryOrder {
                delivery_index,
                expected_sender_position,
                actual_sender_position,
            } => write!(
                formatter,
                "seed-recipient inventory delivery {delivery_index} belongs to sender {actual_sender_position}; expected sender {expected_sender_position}"
            ),
            Self::IntegerConversion => {
                formatter.write_str("seed-delivery integer does not fit its canonical width")
            }
            Self::ArithmeticOverflow => formatter.write_str("seed-delivery arithmetic overflowed"),
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedDeliveryError320 {}

/// Formula-derived raw payload layout for one ordered sender-recipient pair.
///
/// Every selected subset contains both endpoints and remains in the sender's
/// canonical catalog order. The final entry is the endpoints' pair opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedDeliveryLayout320 {
    sender_catalog_layout: PseudorandomZeroSharingSeedCatalogLayout320,
    recipient_position: u16,
    subsets: Box<[ReplicatedRandomSharingSubset]>,
    inclusion_proof_byte_length: usize,
    payload_byte_length: usize,
}

impl PseudorandomZeroSharingSeedDeliveryLayout320 {
    pub(crate) fn derive(
        sender_catalog_layout: PseudorandomZeroSharingSeedCatalogLayout320,
        recipient_position: u16,
    ) -> Result<Self, PseudorandomZeroSharingSeedDeliveryError320> {
        validate_endpoints(
            sender_catalog_layout.contributor_position(),
            recipient_position,
            sender_catalog_layout.participant_count(),
        )?;
        let mut subsets = Vec::new();
        for coordinate in sender_catalog_layout.coordinates()? {
            if let PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(subset) = coordinate
                && subset.contains(recipient_position)?
            {
                subsets.push(subset);
            }
        }
        let inclusion_proof_byte_length =
            PseudorandomZeroSharingSeedCatalogInclusionProof320::canonical_byte_length_for_layout(
                sender_catalog_layout,
            )?;
        let subset_entry_byte_length =
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH
                .checked_add(inclusion_proof_byte_length)
                .ok_or(PseudorandomZeroSharingSeedDeliveryError320::ArithmeticOverflow)?;
        let subset_payload_byte_length = subsets
            .len()
            .checked_mul(subset_entry_byte_length)
            .ok_or(PseudorandomZeroSharingSeedDeliveryError320::ArithmeticOverflow)?;
        let pair_entry_byte_length = PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH
            .checked_add(inclusion_proof_byte_length)
            .ok_or(PseudorandomZeroSharingSeedDeliveryError320::ArithmeticOverflow)?;
        let payload_byte_length = subset_payload_byte_length
            .checked_add(pair_entry_byte_length)
            .ok_or(PseudorandomZeroSharingSeedDeliveryError320::ArithmeticOverflow)?;
        Ok(Self {
            sender_catalog_layout,
            recipient_position,
            subsets: subsets.into_boxed_slice(),
            inclusion_proof_byte_length,
            payload_byte_length,
        })
    }

    pub(crate) const fn sender_catalog_layout(
        &self,
    ) -> PseudorandomZeroSharingSeedCatalogLayout320 {
        self.sender_catalog_layout
    }

    pub(crate) const fn recipient_position(&self) -> u16 {
        self.recipient_position
    }

    pub(crate) fn subsets(&self) -> &[ReplicatedRandomSharingSubset] {
        &self.subsets
    }

    pub(crate) fn leaf_count(&self) -> Result<usize, PseudorandomZeroSharingSeedDeliveryError320> {
        self.subsets
            .len()
            .checked_add(1)
            .ok_or(PseudorandomZeroSharingSeedDeliveryError320::ArithmeticOverflow)
    }

    pub(crate) const fn inclusion_proof_byte_length(&self) -> usize {
        self.inclusion_proof_byte_length
    }

    pub(crate) const fn payload_byte_length(&self) -> usize {
        self.payload_byte_length
    }
}

/// Public semantic descriptor for one private delivery stream.
///
/// The descriptor deliberately omits a plaintext-payload hash. Catalog roots
/// already bind every opening, while a later authenticated mailbox owns exact
/// ciphertext integrity. Adding another public hash of secret openings would
/// create a redundant hiding and query-probability owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedDeliveryDescriptorBody320 {
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    root_inventory_identity: Hash512,
    participant_count: u16,
    sender_position: u16,
    recipient_position: u16,
    payload_byte_length: u64,
}

impl PseudorandomZeroSharingSeedDeliveryDescriptorBody320 {
    fn new(
        root_inventory: &VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
        sender_position: u16,
        recipient_position: u16,
    ) -> Result<Self, PseudorandomZeroSharingSeedDeliveryError320> {
        let root_body = root_inventory.root_body(sender_position).ok_or(
            PseudorandomZeroSharingSeedDeliveryError320::MissingSenderRoot { sender_position },
        )?;
        let layout = PseudorandomZeroSharingSeedDeliveryLayout320::derive(
            root_body.layout(),
            recipient_position,
        )?;
        Ok(Self {
            parameter_identity: root_inventory.body().parameter_identity(),
            preparation_context_identity: root_inventory.body().preparation_context_identity(),
            root_inventory_identity: root_inventory.identity()?,
            participant_count: root_inventory.body().participant_count(),
            sender_position,
            recipient_position,
            payload_byte_length: u64::try_from(layout.payload_byte_length())
                .map_err(|_| PseudorandomZeroSharingSeedDeliveryError320::IntegerConversion)?,
        })
    }

    pub(crate) const fn parameter_identity(self) -> Hash512 {
        self.parameter_identity
    }

    pub(crate) const fn preparation_context_identity(self) -> Hash512 {
        self.preparation_context_identity
    }

    pub(crate) const fn root_inventory_identity(self) -> Hash512 {
        self.root_inventory_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn sender_position(self) -> u16 {
        self.sender_position
    }

    pub(crate) const fn recipient_position(self) -> u16 {
        self.recipient_position
    }

    pub(crate) const fn payload_byte_length(self) -> u64 {
        self.payload_byte_length
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedDeliveryError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_DOMAIN,
                )?,
                CanonicalItem::hash512(self.parameter_identity.into_bytes()),
                CanonicalItem::hash512(self.preparation_context_identity.into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::hash512(self.root_inventory_identity.into_bytes()),
                CanonicalItem::unsigned16(self.participant_count),
                CanonicalItem::unsigned16(self.sender_position),
                CanonicalItem::unsigned16(self.recipient_position),
                CanonicalItem::unsigned64(self.payload_byte_length),
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedDeliveryError320> {
        let tuple = CanonicalTuple::decode(bytes, &delivery_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_DOMAIN,
            DELIVERY_DESCRIPTOR_ITEM_COUNT,
            "seed-delivery descriptor",
        )?;
        require_attempt_ordinal(&tuple.items[3], "seed-delivery descriptor")?;
        let descriptor = Self {
            parameter_identity: read_hash512(
                &tuple.items[1],
                "seed-delivery descriptor",
                "parameter identity",
            )?,
            preparation_context_identity: read_hash512(
                &tuple.items[2],
                "seed-delivery descriptor",
                "preparation context identity",
            )?,
            root_inventory_identity: read_hash512(
                &tuple.items[4],
                "seed-delivery descriptor",
                "root-inventory identity",
            )?,
            participant_count: read_u16(
                &tuple.items[5],
                "seed-delivery descriptor",
                "participant count",
            )?,
            sender_position: read_u16(
                &tuple.items[6],
                "seed-delivery descriptor",
                "sender position",
            )?,
            recipient_position: read_u16(
                &tuple.items[7],
                "seed-delivery descriptor",
                "recipient position",
            )?,
            payload_byte_length: read_u64(
                &tuple.items[8],
                "seed-delivery descriptor",
                "payload byte length",
            )?,
        };
        validate_endpoints(
            descriptor.sender_position,
            descriptor.recipient_position,
            descriptor.participant_count,
        )?;
        Ok(descriptor)
    }

    pub(crate) fn identity(self) -> Result<Hash512, PseudorandomZeroSharingSeedDeliveryError320> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

pub(crate) fn derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320(
    root_inventory: &VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
    sender_position: u16,
    recipient_position: u16,
) -> Result<
    PseudorandomZeroSharingSeedDeliveryDescriptorBody320,
    PseudorandomZeroSharingSeedDeliveryError320,
> {
    PseudorandomZeroSharingSeedDeliveryDescriptorBody320::new(
        root_inventory,
        sender_position,
        recipient_position,
    )
}

/// One bounded opening/proof pair borrowed from the private payload cursor.
///
/// The transport owner may split the raw concatenation across ordinary chunks,
/// but it must present exactly these formula-derived entry boundaries. Debug
/// output never exposes either secret-bearing carrier.
#[derive(Clone, Copy)]
pub(crate) struct PseudorandomZeroSharingSeedDeliveryEntryBytes320<'a> {
    opening_bytes: &'a [u8],
    inclusion_proof_bytes: &'a [u8],
}

impl<'a> PseudorandomZeroSharingSeedDeliveryEntryBytes320<'a> {
    pub(crate) const fn new(opening_bytes: &'a [u8], inclusion_proof_bytes: &'a [u8]) -> Self {
        Self {
            opening_bytes,
            inclusion_proof_bytes,
        }
    }
}

impl fmt::Debug for PseudorandomZeroSharingSeedDeliveryEntryBytes320<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSeedDeliveryEntryBytes320")
            .field("opening_byte_length", &self.opening_bytes.len())
            .field(
                "inclusion_proof_byte_length",
                &self.inclusion_proof_bytes.len(),
            )
            .field("carrier_bytes", &"[redacted]")
            .finish()
    }
}

pub(crate) struct RootInventoryMatchedSubsetSeedDeliveryEntry320 {
    subset: ReplicatedRandomSharingSubset,
    contribution: CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320,
}

impl RootInventoryMatchedSubsetSeedDeliveryEntry320 {
    pub(crate) const fn subset(&self) -> ReplicatedRandomSharingSubset {
        self.subset
    }

    pub(crate) const fn contribution(
        &self,
    ) -> &CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320 {
        &self.contribution
    }
}

impl fmt::Debug for RootInventoryMatchedSubsetSeedDeliveryEntry320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootInventoryMatchedSubsetSeedDeliveryEntry320")
            .field("subset", &self.subset)
            .field("contribution", &"[redacted]")
            .finish()
    }
}

/// One exact payload whose openings all match the sender root selected by the
/// complete semantic root inventory.
///
/// Authenticated mailbox delivery, recipient identity, durable custody, and a
/// signed receipt remain separate. This type is not a preparation capability.
pub(crate) struct RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320 {
    descriptor: PseudorandomZeroSharingSeedDeliveryDescriptorBody320,
    layout: PseudorandomZeroSharingSeedDeliveryLayout320,
    subset_entries: Box<[RootInventoryMatchedSubsetSeedDeliveryEntry320]>,
    pair_contribution: CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320,
}

impl RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320 {
    pub(crate) const fn descriptor(&self) -> PseudorandomZeroSharingSeedDeliveryDescriptorBody320 {
        self.descriptor
    }

    pub(crate) const fn layout(&self) -> &PseudorandomZeroSharingSeedDeliveryLayout320 {
        &self.layout
    }

    pub(crate) fn subset_entries(&self) -> &[RootInventoryMatchedSubsetSeedDeliveryEntry320] {
        &self.subset_entries
    }

    pub(crate) const fn pair_contribution(
        &self,
    ) -> &CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320 {
        &self.pair_contribution
    }

    pub(crate) fn identity(&self) -> Result<Hash512, PseudorandomZeroSharingSeedDeliveryError320> {
        self.descriptor.identity()
    }
}

impl fmt::Debug for RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320")
            .field("descriptor", &self.descriptor)
            .field("layout", &self.layout)
            .field("subset_entry_count", &self.subset_entries.len())
            .field("subset_entries", &"[redacted]")
            .field("pair_contribution", &"[redacted]")
            .finish()
    }
}

pub(crate) fn verify_pseudorandom_zero_sharing_seed_delivery_320(
    root_inventory: &VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
    expected_sender_position: u16,
    expected_recipient_position: u16,
    descriptor_bytes: &[u8],
    entries: &[PseudorandomZeroSharingSeedDeliveryEntryBytes320<'_>],
) -> Result<
    RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320,
    PseudorandomZeroSharingSeedDeliveryError320,
> {
    let expected_descriptor = PseudorandomZeroSharingSeedDeliveryDescriptorBody320::new(
        root_inventory,
        expected_sender_position,
        expected_recipient_position,
    )?;
    let descriptor = PseudorandomZeroSharingSeedDeliveryDescriptorBody320::from_canonical_bytes(
        descriptor_bytes,
    )?;
    require_descriptor_match(descriptor, expected_descriptor)?;

    let root_body = root_inventory.root_body(expected_sender_position).ok_or(
        PseudorandomZeroSharingSeedDeliveryError320::MissingSenderRoot {
            sender_position: expected_sender_position,
        },
    )?;
    let root_body_bytes = root_body.canonical_bytes()?;
    let layout = PseudorandomZeroSharingSeedDeliveryLayout320::derive(
        root_body.layout(),
        expected_recipient_position,
    )?;
    let expected_entry_count = layout.leaf_count()?;
    if entries.len() != expected_entry_count {
        return Err(
            PseudorandomZeroSharingSeedDeliveryError320::DeliveryEntryCount {
                expected: expected_entry_count,
                actual: entries.len(),
            },
        );
    }
    let mut subset_entries = Vec::with_capacity(layout.subsets.len());
    for (subset, entry) in layout
        .subsets
        .iter()
        .copied()
        .zip(&entries[..layout.subsets.len()])
    {
        let (_, contribution) =
            super::pseudorandom_zero_sharing_seed_catalog_320::verify_pseudorandom_zero_sharing_subset_seed_opening_catalog_inclusion_320(
                root_body.layout(),
                subset,
                &root_body_bytes,
                entry.opening_bytes,
                entry.inclusion_proof_bytes,
            )?;
        subset_entries.push(RootInventoryMatchedSubsetSeedDeliveryEntry320 {
            subset,
            contribution,
        });
    }
    let pair_entry = entries.last().ok_or(
        PseudorandomZeroSharingSeedDeliveryError320::DeliveryEntryCount {
            expected: expected_entry_count,
            actual: entries.len(),
        },
    )?;
    let (_, pair_contribution) =
        verify_pseudorandom_zero_sharing_pair_seed_opening_catalog_inclusion_320(
            root_body.layout(),
            expected_recipient_position,
            &root_body_bytes,
            pair_entry.opening_bytes,
            pair_entry.inclusion_proof_bytes,
        )?;
    Ok(RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320 {
        descriptor,
        layout,
        subset_entries: subset_entries.into_boxed_slice(),
        pair_contribution,
    })
}

/// Certificate-free semantic body for one recipient's complete remote seed
/// inventory. Every sender identity is derived from the root inventory and the
/// recipient position, so the body does not repeat a denormalized identity list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedRecipientInventoryBody320 {
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    root_inventory_identity: Hash512,
    participant_count: u16,
    recipient_position: u16,
}

impl PseudorandomZeroSharingSeedRecipientInventoryBody320 {
    pub(crate) const fn parameter_identity(self) -> Hash512 {
        self.parameter_identity
    }

    pub(crate) const fn preparation_context_identity(self) -> Hash512 {
        self.preparation_context_identity
    }

    pub(crate) const fn root_inventory_identity(self) -> Hash512 {
        self.root_inventory_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn recipient_position(self) -> u16 {
        self.recipient_position
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedDeliveryError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.parameter_identity.into_bytes()),
                CanonicalItem::hash512(self.preparation_context_identity.into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::hash512(self.root_inventory_identity.into_bytes()),
                CanonicalItem::unsigned16(self.participant_count),
                CanonicalItem::unsigned16(self.recipient_position),
            ],
        )
        .encode()?)
    }

    pub(crate) fn identity(self) -> Result<Hash512, PseudorandomZeroSharingSeedDeliveryError320> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

/// All remote seed deliveries for one recipient, in canonical sender order.
///
/// This aggregation proves root correspondence only. It has no authenticated
/// mailbox, receipt, durable-state, or preparation-continuation authority.
pub(crate) struct RootInventoryMatchedPseudorandomZeroSharingSeedRecipientInventory320 {
    body: PseudorandomZeroSharingSeedRecipientInventoryBody320,
    deliveries: Box<[RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320]>,
}

impl RootInventoryMatchedPseudorandomZeroSharingSeedRecipientInventory320 {
    pub(crate) const fn body(&self) -> PseudorandomZeroSharingSeedRecipientInventoryBody320 {
        self.body
    }

    pub(crate) fn deliveries(
        &self,
    ) -> &[RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320] {
        &self.deliveries
    }

    pub(crate) fn into_deliveries(
        self,
    ) -> Box<[RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320]> {
        self.deliveries
    }
}

impl fmt::Debug for RootInventoryMatchedPseudorandomZeroSharingSeedRecipientInventory320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootInventoryMatchedPseudorandomZeroSharingSeedRecipientInventory320")
            .field("body", &self.body)
            .field("delivery_count", &self.deliveries.len())
            .field("deliveries", &"[redacted]")
            .finish()
    }
}

pub(crate) fn verify_pseudorandom_zero_sharing_seed_recipient_inventory_320(
    root_inventory: &VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
    recipient_position: u16,
    deliveries: Vec<RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320>,
) -> Result<
    RootInventoryMatchedPseudorandomZeroSharingSeedRecipientInventory320,
    PseudorandomZeroSharingSeedDeliveryError320,
> {
    let participant_count = root_inventory.body().participant_count();
    if recipient_position >= participant_count {
        return Err(
            PseudorandomZeroSharingSeedDeliveryError320::EndpointMismatch {
                sender_position: recipient_position,
                recipient_position,
                participant_count,
            },
        );
    }
    let expected_delivery_count = usize::from(
        participant_count
            .checked_sub(1)
            .ok_or(PseudorandomZeroSharingSeedDeliveryError320::ArithmeticOverflow)?,
    );
    if deliveries.len() != expected_delivery_count {
        return Err(PseudorandomZeroSharingSeedDeliveryError320::DeliveryCount {
            expected: expected_delivery_count,
            actual: deliveries.len(),
        });
    }
    let root_inventory_identity = root_inventory.identity()?;
    for (delivery_index, (delivery, expected_sender_position)) in deliveries
        .iter()
        .zip((0..participant_count).filter(|position| *position != recipient_position))
        .enumerate()
    {
        let descriptor = delivery.descriptor;
        if descriptor.sender_position != expected_sender_position {
            return Err(PseudorandomZeroSharingSeedDeliveryError320::DeliveryOrder {
                delivery_index,
                expected_sender_position,
                actual_sender_position: descriptor.sender_position,
            });
        }
        require_descriptor_field(
            descriptor.recipient_position == recipient_position,
            "recipient position",
        )?;
        require_descriptor_field(
            descriptor.parameter_identity == root_inventory.body().parameter_identity(),
            "parameter identity",
        )?;
        require_descriptor_field(
            descriptor.preparation_context_identity
                == root_inventory.body().preparation_context_identity(),
            "preparation context identity",
        )?;
        require_descriptor_field(
            descriptor.root_inventory_identity == root_inventory_identity,
            "root-inventory identity",
        )?;
        require_descriptor_field(
            descriptor.participant_count == participant_count,
            "participant count",
        )?;
    }
    Ok(
        RootInventoryMatchedPseudorandomZeroSharingSeedRecipientInventory320 {
            body: PseudorandomZeroSharingSeedRecipientInventoryBody320 {
                parameter_identity: root_inventory.body().parameter_identity(),
                preparation_context_identity: root_inventory.body().preparation_context_identity(),
                root_inventory_identity,
                participant_count,
                recipient_position,
            },
            deliveries: deliveries.into_boxed_slice(),
        },
    )
}

fn require_descriptor_match(
    actual: PseudorandomZeroSharingSeedDeliveryDescriptorBody320,
    expected: PseudorandomZeroSharingSeedDeliveryDescriptorBody320,
) -> Result<(), PseudorandomZeroSharingSeedDeliveryError320> {
    require_descriptor_field(
        actual.parameter_identity == expected.parameter_identity,
        "parameter identity",
    )?;
    require_descriptor_field(
        actual.preparation_context_identity == expected.preparation_context_identity,
        "preparation context identity",
    )?;
    require_descriptor_field(
        actual.root_inventory_identity == expected.root_inventory_identity,
        "root-inventory identity",
    )?;
    require_descriptor_field(
        actual.participant_count == expected.participant_count,
        "participant count",
    )?;
    require_descriptor_field(
        actual.sender_position == expected.sender_position,
        "sender position",
    )?;
    require_descriptor_field(
        actual.recipient_position == expected.recipient_position,
        "recipient position",
    )?;
    require_descriptor_field(
        actual.payload_byte_length == expected.payload_byte_length,
        "payload byte length",
    )
}

fn require_descriptor_field(
    matches: bool,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedDeliveryError320> {
    if !matches {
        return Err(PseudorandomZeroSharingSeedDeliveryError320::DescriptorMismatch { field });
    }
    Ok(())
}

fn validate_endpoints(
    sender_position: u16,
    recipient_position: u16,
    participant_count: u16,
) -> Result<(), PseudorandomZeroSharingSeedDeliveryError320> {
    if sender_position >= participant_count
        || recipient_position >= participant_count
        || sender_position == recipient_position
    {
        return Err(
            PseudorandomZeroSharingSeedDeliveryError320::EndpointMismatch {
                sender_position,
                recipient_position,
                participant_count,
            },
        );
    }
    Ok(())
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
    object_kind: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedDeliveryError320> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
        return Err(object_mismatch(object_kind, "schema identifier"));
    }
    if tuple.schema_version != CANONICAL_TUPLE_VERSION {
        return Err(object_mismatch(object_kind, "schema version"));
    }
    if tuple.items.len() != expected_item_count {
        return Err(object_mismatch(object_kind, "item count"));
    }
    let domain_item = &tuple.items[0];
    if domain_item.item_type() != CanonicalItemType::Ascii
        || domain_item.variable_value_bytes()? != expected_domain.as_bytes()
    {
        return Err(object_mismatch(object_kind, "object domain"));
    }
    Ok(())
}

fn require_attempt_ordinal(
    item: &CanonicalItem,
    object_kind: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedDeliveryError320> {
    if read_u16(item, object_kind, "preparation attempt ordinal")? != PREPARATION_ATTEMPT_ORDINAL {
        return Err(object_mismatch(object_kind, "preparation attempt ordinal"));
    }
    Ok(())
}

fn read_hash512(
    item: &CanonicalItem,
    object_kind: &'static str,
    field: &'static str,
) -> Result<Hash512, PseudorandomZeroSharingSeedDeliveryError320> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(object_mismatch(object_kind, field));
    }
    let bytes: [u8; Hash512::BYTE_LENGTH] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| object_mismatch(object_kind, field))?;
    Ok(Hash512::from_bytes(bytes))
}

fn read_u16(
    item: &CanonicalItem,
    object_kind: &'static str,
    field: &'static str,
) -> Result<u16, PseudorandomZeroSharingSeedDeliveryError320> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(object_mismatch(object_kind, field));
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| object_mismatch(object_kind, field))?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u64(
    item: &CanonicalItem,
    object_kind: &'static str,
    field: &'static str,
) -> Result<u64, PseudorandomZeroSharingSeedDeliveryError320> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(object_mismatch(object_kind, field));
    }
    let bytes: [u8; 8] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| object_mismatch(object_kind, field))?;
    Ok(u64::from_le_bytes(bytes))
}

const fn object_mismatch(
    _object_kind: &'static str,
    field: &'static str,
) -> PseudorandomZeroSharingSeedDeliveryError320 {
    PseudorandomZeroSharingSeedDeliveryError320::DescriptorMismatch { field }
}

fn delivery_control_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_DELIVERY_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: DELIVERY_DESCRIPTOR_ITEM_COUNT.max(RECIPIENT_INVENTORY_ITEM_COUNT),
        maximum_item_byte_length: MAXIMUM_DELIVERY_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_DELIVERY_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_DELIVERY_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}
