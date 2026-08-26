use core::fmt;

use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512, Roster,
    derive_foundation_roster_parameters, hash_foundation_tuple_512,
};

use super::{
    pseudorandom_zero_sharing_seed_catalog_root_terminal_320::{
        PseudorandomZeroSharingSeedCatalogRootTerminalError320,
        RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    },
    pseudorandom_zero_sharing_seed_catalog_signature_320::ML_DSA_65_SIGNATURE_BYTE_LENGTH,
    pseudorandom_zero_sharing_seed_delivery_320::{
        PseudorandomZeroSharingSeedDeliveryError320,
        RootInventoryMatchedPseudorandomZeroSharingSeedRecipientInventory320,
        verify_pseudorandom_zero_sharing_seed_recipient_inventory_320,
    },
    pseudorandom_zero_sharing_seed_mailbox_320::AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320,
};

const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const AUTHENTICATED_RECIPIENT_INVENTORY_ITEM_COUNT: usize = 10;
const RECIPIENT_RECEIPT_BODY_ITEM_COUNT: usize = 8;
const RECIPIENT_RECEIPT_ENVELOPE_ITEM_COUNT: usize = 3;
const CANONICAL_TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const CANONICAL_ITEM_HEADER_BYTE_LENGTH: usize = 6;
const CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH: usize = 4;
const CANONICAL_HOMOGENEOUS_LIST_HEADER_BYTE_LENGTH: usize = 6;
const MAXIMUM_RECEIPT_CONTROL_OBJECT_BYTE_LENGTH: usize = 16 * 1024;
const MAXIMUM_RECEIPT_CONTROL_OBJECT_ITEM_COUNT: usize = 32;
const MAXIMUM_RECEIPT_CONTROL_OBJECT_ITEM_BYTE_LENGTH: usize = 12 * 1024;
const MAXIMUM_RECEIPT_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 64 * 1024;

pub(crate) const PSEUDORANDOM_ZERO_SHARING_AUTHENTICATED_SEED_RECIPIENT_INVENTORY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/authenticated-seed-recipient-inventory";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_AUTHENTICATED_SEED_RECIPIENT_INVENTORY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/authenticated-seed-recipient-inventory-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-recipient-receipt";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-recipient-receipt-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-recipient-receipt-envelope";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-recipient-receipt-envelope-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/preparation/seed-recipient-receipt";

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + RECIPIENT_RECEIPT_BODY_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_DOMAIN.len()
        + 4 * Hash512::BYTE_LENGTH
        + 3 * size_of::<u16>();
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + RECIPIENT_RECEIPT_ENVELOPE_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_DOMAIN.len()
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_BYTE_LENGTH
        + ML_DSA_65_SIGNATURE_BYTE_LENGTH;

pub(crate) fn pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_body_byte_length(
    participant_count: u16,
) -> Result<usize, PseudorandomZeroSharingSeedReceiptError320> {
    if derive_foundation_roster_parameters(participant_count).is_none() {
        return Err(PseudorandomZeroSharingSeedReceiptError320::GeometryMismatch);
    }
    let delivery_count = usize::from(
        participant_count
            .checked_sub(1)
            .ok_or(PseudorandomZeroSharingSeedReceiptError320::GeometryMismatch)?,
    );
    if delivery_count == 0 {
        return Err(PseudorandomZeroSharingSeedReceiptError320::GeometryMismatch);
    }
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        .checked_add(
            AUTHENTICATED_RECIPIENT_INVENTORY_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH,
        )
        .and_then(|length| length.checked_add(CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH))
        .and_then(|length| {
            length.checked_add(
                PSEUDORANDOM_ZERO_SHARING_AUTHENTICATED_SEED_RECIPIENT_INVENTORY_DOMAIN.len(),
            )
        })
        .and_then(|length| length.checked_add(4 * Hash512::BYTE_LENGTH))
        .and_then(|length| length.checked_add(3 * size_of::<u16>()))
        .and_then(|length| length.checked_add(2 * CANONICAL_HOMOGENEOUS_LIST_HEADER_BYTE_LENGTH))
        .and_then(|length| {
            delivery_count
                .checked_mul(2 * Hash512::BYTE_LENGTH)
                .and_then(|identity_bytes| length.checked_add(identity_bytes))
        })
        .ok_or(PseudorandomZeroSharingSeedReceiptError320::ArithmeticOverflow)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedReceiptError320 {
    Canonical(CanonicalCodecError),
    Delivery(PseudorandomZeroSharingSeedDeliveryError320),
    RootTerminal(PseudorandomZeroSharingSeedCatalogRootTerminalError320),
    ObjectMismatch { field: &'static str },
    GeometryMismatch,
    RosterMismatch,
    MalformedSigningVerificationKey,
    SignatureByteLength { expected: usize, actual: usize },
    InvalidRecipientSignature,
    ArithmeticOverflow,
}

impl From<CanonicalCodecError> for PseudorandomZeroSharingSeedReceiptError320 {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<PseudorandomZeroSharingSeedDeliveryError320>
    for PseudorandomZeroSharingSeedReceiptError320
{
    fn from(error: PseudorandomZeroSharingSeedDeliveryError320) -> Self {
        Self::Delivery(error)
    }
}

impl From<PseudorandomZeroSharingSeedCatalogRootTerminalError320>
    for PseudorandomZeroSharingSeedReceiptError320
{
    fn from(error: PseudorandomZeroSharingSeedCatalogRootTerminalError320) -> Self {
        Self::RootTerminal(error)
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedReceiptError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => write!(formatter, "canonical seed-receipt error: {error}"),
            Self::Delivery(error) => write!(formatter, "seed-receipt delivery error: {error}"),
            Self::RootTerminal(error) => {
                write!(formatter, "seed-receipt root-terminal error: {error}")
            }
            Self::ObjectMismatch { field } => {
                write!(formatter, "seed-receipt object has a wrong {field}")
            }
            Self::GeometryMismatch => {
                formatter.write_str("seed-receipt inventory geometry is invalid")
            }
            Self::RosterMismatch => formatter
                .write_str("seed-receipt roster does not match the terminal preparation context"),
            Self::MalformedSigningVerificationKey => formatter
                .write_str("seed-receipt roster contains a malformed ML-DSA-65 verification key"),
            Self::SignatureByteLength { expected, actual } => write!(
                formatter,
                "seed-receipt signature has {actual} bytes; expected {expected}"
            ),
            Self::InvalidRecipientSignature => {
                formatter.write_str("seed-receipt has an invalid recipient signature")
            }
            Self::ArithmeticOverflow => formatter.write_str("seed-receipt arithmetic overflowed"),
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedReceiptError320 {}

/// Derived public identity of every authenticated remote stream accepted by one
/// recipient. Sender positions are implicit in canonical roster order excluding
/// the recipient, while both ordered identity lists bind the exact encrypted
/// carrier semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingAuthenticatedSeedRecipientInventoryBody320 {
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    root_terminal_identity: Hash512,
    participant_count: u16,
    recipient_position: u16,
    semantic_recipient_inventory_identity: Hash512,
    ordered_header_identities: Box<[Hash512]>,
    ordered_manifest_identities: Box<[Hash512]>,
}

impl PseudorandomZeroSharingAuthenticatedSeedRecipientInventoryBody320 {
    pub(crate) const fn parameter_identity(&self) -> Hash512 {
        self.parameter_identity
    }

    pub(crate) const fn preparation_context_identity(&self) -> Hash512 {
        self.preparation_context_identity
    }

    pub(crate) const fn root_terminal_identity(&self) -> Hash512 {
        self.root_terminal_identity
    }

    pub(crate) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn recipient_position(&self) -> u16 {
        self.recipient_position
    }

    pub(crate) const fn semantic_recipient_inventory_identity(&self) -> Hash512 {
        self.semantic_recipient_inventory_identity
    }

    pub(crate) fn ordered_header_identities(&self) -> &[Hash512] {
        &self.ordered_header_identities
    }

    pub(crate) fn ordered_manifest_identities(&self) -> &[Hash512] {
        &self.ordered_manifest_identities
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedReceiptError320> {
        let header_identity_items = self
            .ordered_header_identities
            .iter()
            .map(|identity| CanonicalItem::hash512(identity.into_bytes()))
            .collect::<Vec<_>>();
        let manifest_identity_items = self
            .ordered_manifest_identities
            .iter()
            .map(|identity| CanonicalItem::hash512(identity.into_bytes()))
            .collect::<Vec<_>>();
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_AUTHENTICATED_SEED_RECIPIENT_INVENTORY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.parameter_identity.into_bytes()),
                CanonicalItem::hash512(self.preparation_context_identity.into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::hash512(self.root_terminal_identity.into_bytes()),
                CanonicalItem::unsigned16(self.participant_count),
                CanonicalItem::unsigned16(self.recipient_position),
                CanonicalItem::hash512(self.semantic_recipient_inventory_identity.into_bytes()),
                CanonicalItem::homogeneous_list(
                    CanonicalItemType::Hash512,
                    &header_identity_items,
                )?,
                CanonicalItem::homogeneous_list(
                    CanonicalItemType::Hash512,
                    &manifest_identity_items,
                )?,
            ],
        )
        .encode()?)
    }

    pub(crate) fn identity(&self) -> Result<Hash512, PseudorandomZeroSharingSeedReceiptError320> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_AUTHENTICATED_SEED_RECIPIENT_INVENTORY_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

/// Complete authenticated remote delivery inventory for one recipient.
///
/// It has no recipient signature, all-recipient terminal, durable-state output,
/// or preparation-continuation authority.
pub(crate) struct AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320 {
    body: PseudorandomZeroSharingAuthenticatedSeedRecipientInventoryBody320,
    root_matched_inventory: RootInventoryMatchedPseudorandomZeroSharingSeedRecipientInventory320,
}

impl AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320 {
    pub(crate) const fn body(
        &self,
    ) -> &PseudorandomZeroSharingAuthenticatedSeedRecipientInventoryBody320 {
        &self.body
    }

    pub(crate) const fn root_matched_inventory(
        &self,
    ) -> &RootInventoryMatchedPseudorandomZeroSharingSeedRecipientInventory320 {
        &self.root_matched_inventory
    }

    pub(crate) fn into_root_matched_inventory(
        self,
    ) -> RootInventoryMatchedPseudorandomZeroSharingSeedRecipientInventory320 {
        self.root_matched_inventory
    }
}

impl fmt::Debug for AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320")
            .field("body", &self.body)
            .field("root_matched_inventory", &"[redacted]")
            .finish()
    }
}

pub(crate) fn verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    recipient_position: u16,
    authenticated_deliveries: Vec<AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320>,
) -> Result<
    AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320,
    PseudorandomZeroSharingSeedReceiptError320,
> {
    let ordered_header_identities = authenticated_deliveries
        .iter()
        .map(AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320::header_identity)
        .collect::<Vec<_>>();
    let ordered_manifest_identities = authenticated_deliveries
        .iter()
        .map(AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320::manifest_identity)
        .collect::<Vec<_>>();
    let root_matched_inventory = verify_pseudorandom_zero_sharing_seed_recipient_inventory_320(
        root_terminal,
        recipient_position,
        authenticated_deliveries
            .into_iter()
            .map(AuthenticatedPseudorandomZeroSharingSeedMailboxDelivery320::into_delivery)
            .collect(),
    )?;
    let semantic_body = root_matched_inventory.body();
    let body = PseudorandomZeroSharingAuthenticatedSeedRecipientInventoryBody320 {
        parameter_identity: semantic_body.parameter_identity(),
        preparation_context_identity: semantic_body.preparation_context_identity(),
        root_terminal_identity: semantic_body.root_terminal_identity(),
        participant_count: semantic_body.participant_count(),
        recipient_position: semantic_body.recipient_position(),
        semantic_recipient_inventory_identity: semantic_body.identity()?,
        ordered_header_identities: ordered_header_identities.into_boxed_slice(),
        ordered_manifest_identities: ordered_manifest_identities.into_boxed_slice(),
    };
    let expected_delivery_count = usize::from(
        body.participant_count
            .checked_sub(1)
            .ok_or(PseudorandomZeroSharingSeedReceiptError320::GeometryMismatch)?,
    );
    if body.ordered_header_identities.len() != expected_delivery_count
        || body.ordered_manifest_identities.len() != expected_delivery_count
        || body.canonical_bytes()?.len()
            != pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_body_byte_length(
                body.participant_count,
            )?
    {
        return Err(PseudorandomZeroSharingSeedReceiptError320::GeometryMismatch);
    }
    Ok(
        AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320 {
            body,
            root_matched_inventory,
        },
    )
}

/// Canonical message signed by one recipient after every remote authenticated
/// stream has passed source verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedRecipientReceiptBody320 {
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    root_terminal_identity: Hash512,
    participant_count: u16,
    recipient_position: u16,
    authenticated_recipient_inventory_identity: Hash512,
}

impl PseudorandomZeroSharingSeedRecipientReceiptBody320 {
    pub(crate) fn new(
        inventory: &AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320,
    ) -> Result<Self, PseudorandomZeroSharingSeedReceiptError320> {
        Ok(Self {
            parameter_identity: inventory.body.parameter_identity,
            preparation_context_identity: inventory.body.preparation_context_identity,
            root_terminal_identity: inventory.body.root_terminal_identity,
            participant_count: inventory.body.participant_count,
            recipient_position: inventory.body.recipient_position,
            authenticated_recipient_inventory_identity: inventory.body.identity()?,
        })
    }

    pub(crate) const fn parameter_identity(self) -> Hash512 {
        self.parameter_identity
    }

    pub(crate) const fn preparation_context_identity(self) -> Hash512 {
        self.preparation_context_identity
    }

    pub(crate) const fn root_terminal_identity(self) -> Hash512 {
        self.root_terminal_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn recipient_position(self) -> u16 {
        self.recipient_position
    }

    pub(crate) const fn authenticated_recipient_inventory_identity(self) -> Hash512 {
        self.authenticated_recipient_inventory_identity
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedReceiptError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.parameter_identity.into_bytes()),
                CanonicalItem::hash512(self.preparation_context_identity.into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::hash512(self.root_terminal_identity.into_bytes()),
                CanonicalItem::unsigned16(self.participant_count),
                CanonicalItem::unsigned16(self.recipient_position),
                CanonicalItem::hash512(
                    self.authenticated_recipient_inventory_identity.into_bytes(),
                ),
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected: Self,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedReceiptError320> {
        let tuple = CanonicalTuple::decode(bytes, &receipt_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_DOMAIN,
            RECIPIENT_RECEIPT_BODY_ITEM_COUNT,
        )?;
        require_hash512(
            &tuple.items[1],
            expected.parameter_identity,
            "parameter identity",
        )?;
        require_hash512(
            &tuple.items[2],
            expected.preparation_context_identity,
            "preparation context identity",
        )?;
        require_u16(
            &tuple.items[3],
            PREPARATION_ATTEMPT_ORDINAL,
            "preparation attempt ordinal",
        )?;
        require_hash512(
            &tuple.items[4],
            expected.root_terminal_identity,
            "root-terminal identity",
        )?;
        require_u16(
            &tuple.items[5],
            expected.participant_count,
            "participant count",
        )?;
        require_u16(
            &tuple.items[6],
            expected.recipient_position,
            "recipient position",
        )?;
        require_hash512(
            &tuple.items[7],
            expected.authenticated_recipient_inventory_identity,
            "authenticated recipient-inventory identity",
        )?;
        Ok(expected)
    }

    fn decode(bytes: &[u8]) -> Result<Self, PseudorandomZeroSharingSeedReceiptError320> {
        let tuple = CanonicalTuple::decode(bytes, &receipt_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_DOMAIN,
            RECIPIENT_RECEIPT_BODY_ITEM_COUNT,
        )?;
        require_u16(
            &tuple.items[3],
            PREPARATION_ATTEMPT_ORDINAL,
            "preparation attempt ordinal",
        )?;
        let participant_count = read_u16(&tuple.items[5], "participant count")?;
        if derive_foundation_roster_parameters(participant_count).is_none() {
            return Err(PseudorandomZeroSharingSeedReceiptError320::GeometryMismatch);
        }
        let recipient_position = read_u16(&tuple.items[6], "recipient position")?;
        if recipient_position >= participant_count {
            return Err(PseudorandomZeroSharingSeedReceiptError320::GeometryMismatch);
        }
        Ok(Self {
            parameter_identity: read_hash512(&tuple.items[1], "parameter identity")?,
            preparation_context_identity: read_hash512(
                &tuple.items[2],
                "preparation context identity",
            )?,
            root_terminal_identity: read_hash512(&tuple.items[4], "root-terminal identity")?,
            participant_count,
            recipient_position,
            authenticated_recipient_inventory_identity: read_hash512(
                &tuple.items[7],
                "authenticated recipient-inventory identity",
            )?,
        })
    }

    pub(crate) fn identity(self) -> Result<Hash512, PseudorandomZeroSharingSeedReceiptError320> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

/// Detached recipient ML-DSA-65 signature over one complete authenticated
/// inventory.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSignedSeedRecipientReceiptEnvelope320 {
    receipt_body: PseudorandomZeroSharingSeedRecipientReceiptBody320,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl PseudorandomZeroSharingSignedSeedRecipientReceiptEnvelope320 {
    pub(crate) const fn new(
        receipt_body: PseudorandomZeroSharingSeedRecipientReceiptBody320,
        signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self {
            receipt_body,
            signature,
        }
    }

    pub(crate) const fn receipt_body(&self) -> PseudorandomZeroSharingSeedRecipientReceiptBody320 {
        self.receipt_body
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedReceiptError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_DOMAIN,
                )?,
                CanonicalItem::variable_bytes(self.receipt_body.canonical_bytes()?)?,
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    pub(crate) fn from_canonical_bytes(
        expected_receipt_body: PseudorandomZeroSharingSeedRecipientReceiptBody320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedReceiptError320> {
        let tuple = CanonicalTuple::decode(bytes, &receipt_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_DOMAIN,
            RECIPIENT_RECEIPT_ENVELOPE_ITEM_COUNT,
        )?;
        if tuple.items[1].item_type() != CanonicalItemType::RawBytes {
            return Err(receipt_object_mismatch("receipt body"));
        }
        let receipt_body =
            PseudorandomZeroSharingSeedRecipientReceiptBody320::from_canonical_bytes(
                expected_receipt_body,
                tuple.items[1].variable_value_bytes()?,
            )?;
        if tuple.items[2].item_type() != CanonicalItemType::RawBytes {
            return Err(receipt_object_mismatch("signature"));
        }
        let signature = tuple.items[2].canonical_bytes().try_into().map_err(|_| {
            PseudorandomZeroSharingSeedReceiptError320::SignatureByteLength {
                expected: ML_DSA_65_SIGNATURE_BYTE_LENGTH,
                actual: tuple.items[2].canonical_bytes().len(),
            }
        })?;
        Ok(Self {
            receipt_body,
            signature,
        })
    }

    fn decode(bytes: &[u8]) -> Result<Self, PseudorandomZeroSharingSeedReceiptError320> {
        let tuple = CanonicalTuple::decode(bytes, &receipt_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_DOMAIN,
            RECIPIENT_RECEIPT_ENVELOPE_ITEM_COUNT,
        )?;
        if tuple.items[1].item_type() != CanonicalItemType::RawBytes {
            return Err(receipt_object_mismatch("receipt body"));
        }
        let receipt_body = PseudorandomZeroSharingSeedRecipientReceiptBody320::decode(
            tuple.items[1].variable_value_bytes()?,
        )?;
        if tuple.items[2].item_type() != CanonicalItemType::RawBytes {
            return Err(receipt_object_mismatch("signature"));
        }
        let signature = tuple.items[2].canonical_bytes().try_into().map_err(|_| {
            PseudorandomZeroSharingSeedReceiptError320::SignatureByteLength {
                expected: ML_DSA_65_SIGNATURE_BYTE_LENGTH,
                actual: tuple.items[2].canonical_bytes().len(),
            }
        })?;
        Ok(Self {
            receipt_body,
            signature,
        })
    }

    pub(crate) fn identity(&self) -> Result<Hash512, PseudorandomZeroSharingSeedReceiptError320> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

impl fmt::Debug for PseudorandomZeroSharingSignedSeedRecipientReceiptEnvelope320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSignedSeedRecipientReceiptEnvelope320")
            .field("receipt_body", &self.receipt_body)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Publicly verifiable recipient attestation over one opaque authenticated
/// delivery-inventory identity.
///
/// An honest recipient creates the signed body only after local delivery
/// verification. A corrupt recipient can attest to an arbitrary inventory
/// identity, so this type proves only the roster signature and exact root-
/// terminal scope. It has no local-delivery or continuation authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RosterSignedPseudorandomZeroSharingSeedRecipientReceipt320 {
    receipt_body: PseudorandomZeroSharingSeedRecipientReceiptBody320,
    receipt_envelope_identity: Hash512,
}

impl RosterSignedPseudorandomZeroSharingSeedRecipientReceipt320 {
    pub(crate) const fn receipt_body(self) -> PseudorandomZeroSharingSeedRecipientReceiptBody320 {
        self.receipt_body
    }

    pub(crate) const fn receipt_envelope_identity(self) -> Hash512 {
        self.receipt_envelope_identity
    }
}

pub(crate) fn verify_pseudorandom_zero_sharing_seed_recipient_receipt_announcement_320(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    roster: &Roster,
    expected_recipient_position: u16,
    receipt_envelope_bytes: &[u8],
) -> Result<
    RosterSignedPseudorandomZeroSharingSeedRecipientReceipt320,
    PseudorandomZeroSharingSeedReceiptError320,
> {
    validate_roster_for_terminal(root_terminal, roster)?;
    let root_inventory_body = root_terminal.root_inventory().body();
    let receipt_envelope = PseudorandomZeroSharingSignedSeedRecipientReceiptEnvelope320::decode(
        receipt_envelope_bytes,
    )?;
    let receipt_body = receipt_envelope.receipt_body;
    if receipt_body.parameter_identity != root_inventory_body.parameter_identity() {
        return Err(receipt_object_mismatch("parameter identity"));
    }
    if receipt_body.preparation_context_identity
        != root_inventory_body.preparation_context_identity()
    {
        return Err(receipt_object_mismatch("preparation context identity"));
    }
    if receipt_body.root_terminal_identity != root_terminal.identity()? {
        return Err(receipt_object_mismatch("root-terminal identity"));
    }
    if receipt_body.participant_count != root_inventory_body.participant_count() {
        return Err(receipt_object_mismatch("participant count"));
    }
    if receipt_body.recipient_position != expected_recipient_position {
        return Err(receipt_object_mismatch("recipient position"));
    }
    let recipient_entry = roster
        .entries
        .get(usize::from(expected_recipient_position))
        .filter(|entry| entry.roster_position == expected_recipient_position)
        .ok_or(PseudorandomZeroSharingSeedReceiptError320::RosterMismatch)?;
    let verification_key = ml_dsa_65::PublicKey::try_from_bytes(
        recipient_entry.signing_verification_key,
    )
    .map_err(|_| PseudorandomZeroSharingSeedReceiptError320::MalformedSigningVerificationKey)?;
    if !verification_key.verify(
        &receipt_body.canonical_bytes()?,
        &receipt_envelope.signature,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_SIGNATURE_CONTEXT,
    ) {
        return Err(PseudorandomZeroSharingSeedReceiptError320::InvalidRecipientSignature);
    }
    Ok(RosterSignedPseudorandomZeroSharingSeedRecipientReceipt320 {
        receipt_body,
        receipt_envelope_identity: receipt_envelope.identity()?,
    })
}

/// Positive roster signature over one complete authenticated recipient
/// inventory.
///
/// This result has no all-recipient terminal, durable state, burn output, seed
/// combination authority, or preparation-continuation authority.
pub(crate) struct RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320 {
    recipient_inventory: AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320,
    receipt_body: PseudorandomZeroSharingSeedRecipientReceiptBody320,
    receipt_envelope_identity: Hash512,
}

impl RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320 {
    pub(crate) const fn recipient_inventory(
        &self,
    ) -> &AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320 {
        &self.recipient_inventory
    }

    pub(crate) const fn receipt_body(&self) -> PseudorandomZeroSharingSeedRecipientReceiptBody320 {
        self.receipt_body
    }

    pub(crate) const fn receipt_envelope_identity(&self) -> Hash512 {
        self.receipt_envelope_identity
    }

    pub(crate) fn into_recipient_inventory(
        self,
    ) -> AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320 {
        self.recipient_inventory
    }
}

impl fmt::Debug for RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320")
            .field("receipt_body", &self.receipt_body)
            .field("receipt_envelope_identity", &self.receipt_envelope_identity)
            .field("recipient_inventory", &"[redacted]")
            .finish()
    }
}

pub(crate) fn verify_pseudorandom_zero_sharing_seed_recipient_receipt_320(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    roster: &Roster,
    recipient_inventory: AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320,
    receipt_envelope_bytes: &[u8],
) -> Result<
    RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
    PseudorandomZeroSharingSeedReceiptError320,
> {
    validate_roster_for_terminal(root_terminal, roster)?;
    let expected_receipt_body =
        PseudorandomZeroSharingSeedRecipientReceiptBody320::new(&recipient_inventory)?;
    if expected_receipt_body.root_terminal_identity != root_terminal.identity()? {
        return Err(receipt_object_mismatch("root-terminal identity"));
    }
    let recipient_position = expected_receipt_body.recipient_position;
    let roster_signed_receipt =
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_announcement_320(
            root_terminal,
            roster,
            recipient_position,
            receipt_envelope_bytes,
        )?;
    if roster_signed_receipt.receipt_body() != expected_receipt_body {
        return Err(receipt_object_mismatch("authenticated recipient inventory"));
    }
    Ok(
        RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320 {
            recipient_inventory,
            receipt_body: expected_receipt_body,
            receipt_envelope_identity: roster_signed_receipt.receipt_envelope_identity(),
        },
    )
}

fn validate_roster_for_terminal(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    roster: &Roster,
) -> Result<(), PseudorandomZeroSharingSeedReceiptError320> {
    roster
        .validate()
        .map_err(|_| PseudorandomZeroSharingSeedReceiptError320::RosterMismatch)?;
    let root_inventory = root_terminal.root_inventory();
    if roster.entries.len() != usize::from(root_inventory.body().participant_count()) {
        return Err(PseudorandomZeroSharingSeedReceiptError320::RosterMismatch);
    }
    let first_root = root_inventory
        .root_body(0)
        .ok_or(PseudorandomZeroSharingSeedReceiptError320::RosterMismatch)?;
    if roster
        .roster_hash()
        .map_err(|_| PseudorandomZeroSharingSeedReceiptError320::RosterMismatch)?
        != first_root.layout().preparation_context().roster_hash()
    {
        return Err(PseudorandomZeroSharingSeedReceiptError320::RosterMismatch);
    }
    Ok(())
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), PseudorandomZeroSharingSeedReceiptError320> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
        return Err(receipt_object_mismatch("schema identifier"));
    }
    if tuple.schema_version != CANONICAL_TUPLE_VERSION {
        return Err(receipt_object_mismatch("schema version"));
    }
    if tuple.items.len() != expected_item_count {
        return Err(receipt_object_mismatch("item count"));
    }
    if tuple.items[0].item_type() != CanonicalItemType::Ascii
        || tuple.items[0].variable_value_bytes()? != expected_domain.as_bytes()
    {
        return Err(receipt_object_mismatch("object domain"));
    }
    Ok(())
}

fn require_hash512(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedReceiptError320> {
    if item.item_type() != CanonicalItemType::Hash512
        || item.canonical_bytes() != expected.as_bytes()
    {
        return Err(receipt_object_mismatch(field));
    }
    Ok(())
}

fn read_hash512(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<Hash512, PseudorandomZeroSharingSeedReceiptError320> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(receipt_object_mismatch(field));
    }
    let bytes: [u8; Hash512::BYTE_LENGTH] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| receipt_object_mismatch(field))?;
    Ok(Hash512::from_bytes(bytes))
}

fn require_u16(
    item: &CanonicalItem,
    expected: u16,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedReceiptError320> {
    if item.item_type() != CanonicalItemType::Unsigned16
        || item.canonical_bytes() != expected.to_le_bytes()
    {
        return Err(receipt_object_mismatch(field));
    }
    Ok(())
}

fn read_u16(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u16, PseudorandomZeroSharingSeedReceiptError320> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(receipt_object_mismatch(field));
    }
    let bytes: [u8; size_of::<u16>()] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| receipt_object_mismatch(field))?;
    Ok(u16::from_le_bytes(bytes))
}

fn receipt_object_mismatch(field: &'static str) -> PseudorandomZeroSharingSeedReceiptError320 {
    PseudorandomZeroSharingSeedReceiptError320::ObjectMismatch { field }
}

fn receipt_control_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_RECEIPT_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_RECEIPT_CONTROL_OBJECT_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_RECEIPT_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 3,
        maximum_cumulative_work_byte_length: MAXIMUM_RECEIPT_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_RECEIPT_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}
