use core::fmt;

use fips204::{
    ml_dsa_65,
    traits::{SerDes, Signer, Verifier},
};
use zeroize::Zeroizing;

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
    pseudorandom_zero_sharing_seed_receipt_320::{
        PseudorandomZeroSharingSeedReceiptError320,
        RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
        RosterSignedPseudorandomZeroSharingSeedRecipientReceipt320,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_announcement_320,
    },
};

const RECEIPT_INVENTORY_PREFIX_ITEM_COUNT: usize = 2;
const TERMINAL_BODY_ITEM_COUNT: usize = 2;
const ENDORSEMENT_AUTHORIZATION_BODY_ITEM_COUNT: usize = 3;
const ENDORSEMENT_ENVELOPE_ITEM_COUNT: usize = 3;
const TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT: usize = 2;
const CANONICAL_TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const CANONICAL_ITEM_HEADER_BYTE_LENGTH: usize = 6;
const CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH: usize = 4;
const MAXIMUM_TERMINAL_CONTROL_OBJECT_BYTE_LENGTH: usize = 131_072;
const MAXIMUM_TERMINAL_CONTROL_OBJECT_ITEM_COUNT: usize = 32;
const MAXIMUM_TERMINAL_CONTROL_OBJECT_ITEM_BYTE_LENGTH: usize = 8_192;
const MAXIMUM_TERMINAL_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH: usize = 262_144;

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_INVENTORY_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-recipient-receipt-inventory";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_INVENTORY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-recipient-receipt-inventory-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-recipient-receipt-terminal";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-recipient-receipt-terminal-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-recipient-receipt-terminal-endorsement-body";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-recipient-receipt-terminal-endorsement-envelope";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_CERTIFICATE_DOMAIN:
    &str = "sealed-lattice/v1/preparation/seed-recipient-receipt-terminal-certificate";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_CERTIFICATE_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-recipient-receipt-terminal-certificate-identity";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT:
    &[u8] = b"sealed-lattice/v1/preparation/seed-recipient-receipt-terminal";

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_BODY_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + TERMINAL_BODY_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_BODY_DOMAIN.len()
        + Hash512::BYTE_LENGTH;
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + ENDORSEMENT_AUTHORIZATION_BODY_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_DOMAIN.len()
        + Hash512::BYTE_LENGTH
        + size_of::<u16>();
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH: usize =
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        + ENDORSEMENT_ENVELOPE_ITEM_COUNT * CANONICAL_ITEM_HEADER_BYTE_LENGTH
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_DOMAIN.len()
        + CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
        + PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_BYTE_LENGTH
        + ML_DSA_65_SIGNATURE_BYTE_LENGTH;

pub(crate) fn pseudorandom_zero_sharing_seed_recipient_receipt_inventory_body_byte_length(
    participant_count: u16,
) -> Result<usize, PseudorandomZeroSharingSeedReceiptTerminalError320> {
    if derive_foundation_roster_parameters(participant_count).is_none() {
        return Err(PseudorandomZeroSharingSeedReceiptTerminalError320::GeometryMismatch);
    }
    let receipt_count = usize::from(participant_count);
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        .checked_add(
            RECEIPT_INVENTORY_PREFIX_ITEM_COUNT
                .checked_add(receipt_count)
                .and_then(|item_count| item_count.checked_mul(CANONICAL_ITEM_HEADER_BYTE_LENGTH))
                .ok_or(PseudorandomZeroSharingSeedReceiptTerminalError320::ArithmeticOverflow)?,
        )
        .and_then(|length| length.checked_add(CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH))
        .and_then(|length| {
            length.checked_add(
                PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_INVENTORY_BODY_DOMAIN.len(),
            )
        })
        .and_then(|length| length.checked_add(Hash512::BYTE_LENGTH))
        .and_then(|length| {
            receipt_count
                .checked_mul(Hash512::BYTE_LENGTH)
                .and_then(|receipt_identity_bytes| length.checked_add(receipt_identity_bytes))
        })
        .ok_or(PseudorandomZeroSharingSeedReceiptTerminalError320::ArithmeticOverflow)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedReceiptTerminalError320 {
    Canonical(CanonicalCodecError),
    Receipt {
        recipient_position: u16,
        error: PseudorandomZeroSharingSeedReceiptError320,
    },
    RootTerminal(PseudorandomZeroSharingSeedCatalogRootTerminalError320),
    ObjectMismatch {
        field: &'static str,
    },
    GeometryMismatch,
    RosterMismatch,
    ReceiptCount {
        expected: usize,
        actual: usize,
    },
    ReceiptOrder,
    EndorsementCount {
        expected: usize,
        actual: usize,
    },
    EndorserPositionOutOfRange {
        endorser_position: u16,
        participant_count: u16,
    },
    EndorsementOrder,
    MalformedSigningVerificationKey {
        endorser_position: u16,
    },
    InvalidEndorsementSignature {
        endorser_position: u16,
    },
    RetainedLocalReceiptMismatch {
        field: &'static str,
    },
    EndorserSigningKeyMismatch {
        endorser_position: u16,
    },
    InvalidSignatureRandomness,
    SignatureGenerationFailed {
        endorser_position: u16,
    },
    ArithmeticOverflow,
}

impl From<CanonicalCodecError> for PseudorandomZeroSharingSeedReceiptTerminalError320 {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<PseudorandomZeroSharingSeedCatalogRootTerminalError320>
    for PseudorandomZeroSharingSeedReceiptTerminalError320
{
    fn from(error: PseudorandomZeroSharingSeedCatalogRootTerminalError320) -> Self {
        Self::RootTerminal(error)
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedReceiptTerminalError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => {
                write!(formatter, "canonical seed-receipt terminal error: {error}")
            }
            Self::Receipt {
                recipient_position,
                error,
            } => write!(
                formatter,
                "seed-receipt terminal recipient {recipient_position} failed: {error}"
            ),
            Self::RootTerminal(error) => {
                write!(formatter, "seed-receipt terminal root predecessor failed: {error}")
            }
            Self::ObjectMismatch { field } => {
                write!(formatter, "seed-receipt terminal object has a wrong {field}")
            }
            Self::GeometryMismatch => {
                formatter.write_str("seed-receipt terminal geometry is invalid")
            }
            Self::RosterMismatch => {
                formatter.write_str("seed-receipt terminal roster does not match its predecessor")
            }
            Self::ReceiptCount { expected, actual } => write!(
                formatter,
                "seed-receipt inventory has {actual} receipts; expected {expected}"
            ),
            Self::ReceiptOrder => formatter.write_str(
                "seed-receipt inventory must cover every recipient in canonical roster order",
            ),
            Self::EndorsementCount { expected, actual } => write!(
                formatter,
                "seed-receipt terminal certificate has {actual} endorsements; expected {expected}"
            ),
            Self::EndorserPositionOutOfRange {
                endorser_position,
                participant_count,
            } => write!(
                formatter,
                "seed-receipt terminal endorser {endorser_position} is outside participant count {participant_count}"
            ),
            Self::EndorsementOrder => formatter.write_str(
                "seed-receipt terminal endorsements must cover every participant in canonical roster order",
            ),
            Self::MalformedSigningVerificationKey { endorser_position } => write!(
                formatter,
                "seed-receipt terminal endorser {endorser_position} has a malformed ML-DSA-65 verification key"
            ),
            Self::InvalidEndorsementSignature { endorser_position } => write!(
                formatter,
                "seed-receipt terminal endorser {endorser_position} has an invalid ML-DSA-65 signature"
            ),
            Self::RetainedLocalReceiptMismatch { field } => write!(
                formatter,
                "seed-receipt terminal public inventory does not match the retained local receipt {field}"
            ),
            Self::EndorserSigningKeyMismatch { endorser_position } => write!(
                formatter,
                "seed-receipt terminal signing key does not match roster endorser {endorser_position}"
            ),
            Self::InvalidSignatureRandomness => formatter.write_str(
                "seed-receipt terminal signature randomness must be a nonzero 32-byte value",
            ),
            Self::SignatureGenerationFailed { endorser_position } => write!(
                formatter,
                "seed-receipt terminal signature generation failed for endorser {endorser_position}"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("seed-receipt terminal arithmetic overflowed")
            }
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedReceiptTerminalError320 {}

/// Certificate-free semantic body for one complete roster-ordered receipt set.
///
/// The selected root-terminal identity transitively binds parameter,
/// preparation, attempt, and roster. Each receipt-body identity binds its
/// recipient and authenticated delivery-inventory identity. Signature-carrier
/// randomness is deliberately excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedRecipientReceiptInventoryBody320 {
    root_terminal_identity: Hash512,
    participant_count: u16,
    receipt_body_identities: Box<[Hash512]>,
}

impl PseudorandomZeroSharingSeedRecipientReceiptInventoryBody320 {
    fn new(
        root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
        receipts: &[RosterSignedPseudorandomZeroSharingSeedRecipientReceipt320],
    ) -> Result<Self, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        let participant_count = root_terminal.root_inventory().body().participant_count();
        let expected_receipt_count = usize::from(participant_count);
        if receipts.len() != expected_receipt_count {
            return Err(
                PseudorandomZeroSharingSeedReceiptTerminalError320::ReceiptCount {
                    expected: expected_receipt_count,
                    actual: receipts.len(),
                },
            );
        }
        let mut receipt_body_identities = Vec::with_capacity(expected_receipt_count);
        for (recipient_index, receipt) in receipts.iter().enumerate() {
            let expected_recipient_position = u16::try_from(recipient_index).map_err(|_| {
                PseudorandomZeroSharingSeedReceiptTerminalError320::ArithmeticOverflow
            })?;
            if receipt.receipt_body().recipient_position() != expected_recipient_position {
                return Err(PseudorandomZeroSharingSeedReceiptTerminalError320::ReceiptOrder);
            }
            receipt_body_identities.push(receipt.receipt_body().identity().map_err(|error| {
                PseudorandomZeroSharingSeedReceiptTerminalError320::Receipt {
                    recipient_position: expected_recipient_position,
                    error,
                }
            })?);
        }
        Ok(Self {
            root_terminal_identity: root_terminal.identity()?,
            participant_count,
            receipt_body_identities: receipt_body_identities.into_boxed_slice(),
        })
    }

    pub(crate) const fn root_terminal_identity(&self) -> Hash512 {
        self.root_terminal_identity
    }

    pub(crate) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(crate) fn receipt_body_identities(&self) -> &[Hash512] {
        &self.receipt_body_identities
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        let mut items = Vec::with_capacity(
            RECEIPT_INVENTORY_PREFIX_ITEM_COUNT + self.receipt_body_identities.len(),
        );
        items.push(CanonicalItem::nonempty_ascii(
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_INVENTORY_BODY_DOMAIN,
        )?);
        items.push(CanonicalItem::hash512(
            self.root_terminal_identity.into_bytes(),
        ));
        items.extend(
            self.receipt_body_identities
                .iter()
                .map(|identity| CanonicalItem::hash512(identity.into_bytes())),
        );
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            items,
        )
        .encode()?)
    }

    pub(crate) fn identity(
        &self,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_INVENTORY_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

/// Complete ordered public receipt inventory after every individual recipient
/// signature passes.
///
/// This result does not prove the opaque inventory claimed by a corrupt
/// recipient, and it has no common-view or continuation authority until the
/// all-roster terminal passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320 {
    body: PseudorandomZeroSharingSeedRecipientReceiptInventoryBody320,
    receipts: Box<[RosterSignedPseudorandomZeroSharingSeedRecipientReceipt320]>,
}

impl VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320 {
    pub(crate) const fn body(
        &self,
    ) -> &PseudorandomZeroSharingSeedRecipientReceiptInventoryBody320 {
        &self.body
    }

    pub(crate) fn receipts(&self) -> &[RosterSignedPseudorandomZeroSharingSeedRecipientReceipt320] {
        &self.receipts
    }

    pub(crate) fn identity(
        &self,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        self.body.identity()
    }
}

pub(crate) fn verify_pseudorandom_zero_sharing_seed_recipient_receipt_inventory_320(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    roster: &Roster,
    receipt_envelope_bytes: &[&[u8]],
) -> Result<
    VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320,
    PseudorandomZeroSharingSeedReceiptTerminalError320,
> {
    validate_roster(root_terminal, roster)?;
    let participant_count = root_terminal.root_inventory().body().participant_count();
    let expected_receipt_count = usize::from(participant_count);
    if receipt_envelope_bytes.len() != expected_receipt_count {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::ReceiptCount {
                expected: expected_receipt_count,
                actual: receipt_envelope_bytes.len(),
            },
        );
    }
    let receipts = receipt_envelope_bytes
        .iter()
        .enumerate()
        .map(|(recipient_index, envelope_bytes)| {
            let recipient_position = u16::try_from(recipient_index).map_err(|_| {
                PseudorandomZeroSharingSeedReceiptTerminalError320::ArithmeticOverflow
            })?;
            verify_pseudorandom_zero_sharing_seed_recipient_receipt_announcement_320(
                root_terminal,
                roster,
                recipient_position,
                envelope_bytes,
            )
            .map_err(|error| {
                PseudorandomZeroSharingSeedReceiptTerminalError320::Receipt {
                    recipient_position,
                    error,
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let body =
        PseudorandomZeroSharingSeedRecipientReceiptInventoryBody320::new(root_terminal, &receipts)?;
    if body.canonical_bytes()?.len()
        != pseudorandom_zero_sharing_seed_recipient_receipt_inventory_body_byte_length(
            participant_count,
        )?
    {
        return Err(PseudorandomZeroSharingSeedReceiptTerminalError320::GeometryMismatch);
    }
    Ok(
        VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320 {
            body,
            receipts: receipts.into_boxed_slice(),
        },
    )
}

/// Semantic common-view target signed by every roster participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320 {
    receipt_inventory_identity: Hash512,
    participant_count: u16,
}

impl PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320 {
    pub(crate) fn new(
        receipt_inventory: &VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320,
    ) -> Result<Self, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        Ok(Self {
            receipt_inventory_identity: receipt_inventory.identity()?,
            participant_count: receipt_inventory.body.participant_count,
        })
    }

    pub(crate) const fn receipt_inventory_identity(self) -> Hash512 {
        self.receipt_inventory_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.receipt_inventory_identity.into_bytes()),
            ],
        )
        .encode()?)
    }

    pub(crate) fn identity(
        self,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    fn from_canonical_bytes(
        receipt_inventory: &VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        let expected = Self::new(receipt_inventory)?;
        let tuple = CanonicalTuple::decode(bytes, &terminal_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_BODY_DOMAIN,
            TERMINAL_BODY_ITEM_COUNT,
        )?;
        require_hash512(
            &tuple.items[1],
            expected.receipt_inventory_identity,
            "receipt-inventory identity",
        )?;
        Ok(expected)
    }
}

/// Public receipt inventory and terminal body after the endorser's public
/// receipt has been matched to its retained authenticated local receipt.
///
/// This is the exact alternative that durable state must lock before signing.
/// It contains no signing key, signature randomness, burn result, seed-
/// combination authority, coin-opening authority, or preparation-continuation
/// authority.
#[derive(Debug, Clone)]
pub(crate) struct PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320 {
    root_terminal: RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    receipt_inventory: VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320,
    terminal_body: PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320,
    endorser_position: u16,
}

impl PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320 {
    pub(crate) const fn root_terminal(
        &self,
    ) -> &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320 {
        &self.root_terminal
    }

    pub(crate) const fn receipt_inventory(
        &self,
    ) -> &VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320 {
        &self.receipt_inventory
    }

    pub(crate) const fn terminal_body(
        &self,
    ) -> PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320 {
        self.terminal_body
    }

    pub(crate) const fn endorser_position(&self) -> u16 {
        self.endorser_position
    }
}

pub(crate) fn prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
    root_terminal: RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    receipt_inventory: VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320,
    roster: &Roster,
    retained_local_receipt: &RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
) -> Result<
    PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320,
    PseudorandomZeroSharingSeedReceiptTerminalError320,
> {
    validate_roster(&root_terminal, roster)?;
    if receipt_inventory.body.root_terminal_identity != root_terminal.identity()? {
        return Err(terminal_object_mismatch("root-terminal identity"));
    }
    let terminal_body =
        PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320::new(&receipt_inventory)?;
    let retained_receipt_body = retained_local_receipt.receipt_body();
    let endorser_position = retained_receipt_body.recipient_position();
    validate_endorser_position(terminal_body, endorser_position)?;
    let public_receipt = receipt_inventory
        .receipts()
        .get(usize::from(endorser_position))
        .ok_or(
            PseudorandomZeroSharingSeedReceiptTerminalError320::EndorserPositionOutOfRange {
                endorser_position,
                participant_count: terminal_body.participant_count(),
            },
        )?;
    if public_receipt.receipt_body() != retained_receipt_body {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::RetainedLocalReceiptMismatch {
                field: "body",
            },
        );
    }
    if public_receipt.receipt_envelope_identity()
        != retained_local_receipt.receipt_envelope_identity()
    {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::RetainedLocalReceiptMismatch {
                field: "envelope identity",
            },
        );
    }
    Ok(
        PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320 {
            root_terminal,
            receipt_inventory,
            terminal_body,
            endorser_position,
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementAuthorizationBody320
{
    terminal_body_identity: Hash512,
    endorser_position: u16,
}

impl PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementAuthorizationBody320 {
    pub(crate) fn new(
        terminal_body: PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320,
        endorser_position: u16,
    ) -> Result<Self, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        validate_endorser_position(terminal_body, endorser_position)?;
        Ok(Self {
            terminal_body_identity: terminal_body.identity()?,
            endorser_position,
        })
    }

    pub(crate) const fn endorser_position(self) -> u16 {
        self.endorser_position
    }

    pub(crate) fn canonical_bytes(
        self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_DOMAIN,
                )?,
                CanonicalItem::hash512(self.terminal_body_identity.into_bytes()),
                CanonicalItem::unsigned16(self.endorser_position),
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_terminal_body: PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        let tuple = CanonicalTuple::decode(bytes, &terminal_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_DOMAIN,
            ENDORSEMENT_AUTHORIZATION_BODY_ITEM_COUNT,
        )?;
        require_hash512(
            &tuple.items[1],
            expected_terminal_body.identity()?,
            "terminal-body identity",
        )?;
        Self::new(
            expected_terminal_body,
            read_u16(&tuple.items[2], "endorser position")?,
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320 {
    authorization_body:
        PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementAuthorizationBody320,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320 {
    pub(crate) const fn new(
        authorization_body: PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementAuthorizationBody320,
        signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self {
            authorization_body,
            signature,
        }
    }

    pub(crate) const fn authorization_body(
        &self,
    ) -> PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementAuthorizationBody320 {
        self.authorization_body
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_DOMAIN,
                )?,
                CanonicalItem::variable_bytes(self.authorization_body.canonical_bytes()?)?,
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_terminal_body: PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        let tuple = CanonicalTuple::decode(bytes, &terminal_control_object_decode_limits())?;
        require_object_header(
            &tuple,
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_DOMAIN,
            ENDORSEMENT_ENVELOPE_ITEM_COUNT,
        )?;
        if tuple.items[1].item_type() != CanonicalItemType::RawBytes {
            return Err(terminal_object_mismatch("endorsement authorization body"));
        }
        let authorization_body =
            PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementAuthorizationBody320::from_canonical_bytes(
                expected_terminal_body,
                tuple.items[1].variable_value_bytes()?,
            )?;
        if tuple.items[2].item_type() != CanonicalItemType::RawBytes {
            return Err(terminal_object_mismatch("endorsement signature"));
        }
        let signature = tuple.items[2]
            .canonical_bytes()
            .try_into()
            .map_err(|_| terminal_object_mismatch("endorsement signature byte length"))?;
        Ok(Self {
            authorization_body,
            signature,
        })
    }
}

impl fmt::Debug for PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct(
                "PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320",
            )
            .field("authorization_body", &self.authorization_body)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Exact terminal endorsement produced only after the public receipt inventory
/// matches the endorser's retained authenticated local receipt.
///
/// The result is positively decoded and signature-verified before it is
/// returned. It has no all-roster terminal, burn, seed-combination, coin-
/// opening, or preparation-continuation authority.
pub(crate) struct ProducedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320 {
    prepared_endorsement: PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320,
    endorsement_envelope: PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320,
    endorsement_envelope_bytes: Vec<u8>,
}

impl ProducedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320 {
    pub(crate) const fn prepared_endorsement(
        &self,
    ) -> &PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320 {
        &self.prepared_endorsement
    }

    pub(crate) const fn endorsement_envelope(
        &self,
    ) -> &PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320 {
        &self.endorsement_envelope
    }

    pub(crate) fn endorsement_envelope_bytes(&self) -> &[u8] {
        &self.endorsement_envelope_bytes
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320,
        PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320,
        Vec<u8>,
    ) {
        (
            self.prepared_endorsement,
            self.endorsement_envelope,
            self.endorsement_envelope_bytes,
        )
    }
}

impl fmt::Debug for ProducedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct(
                "ProducedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320",
            )
            .field("terminal_body", &self.prepared_endorsement.terminal_body)
            .field(
                "endorser_position",
                &self.prepared_endorsement.endorser_position,
            )
            .field(
                "endorsement_envelope_byte_length",
                &self.endorsement_envelope_bytes.len(),
            )
            .field("endorsement_signature", &"[redacted]")
            .finish()
    }
}

pub(crate) fn produce_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
    prepared_endorsement: PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320,
    roster: &Roster,
    endorser_signing_key: &ml_dsa_65::PrivateKey,
    signature_randomness: [u8; 32],
) -> Result<
    ProducedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320,
    PseudorandomZeroSharingSeedReceiptTerminalError320,
> {
    let authorization_body =
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_signature_320(
            &prepared_endorsement,
            roster,
        )?;
    let endorser_position = prepared_endorsement.endorser_position;
    let roster_entry = roster
        .entries
        .get(usize::from(endorser_position))
        .filter(|entry| entry.roster_position == endorser_position)
        .ok_or(PseudorandomZeroSharingSeedReceiptTerminalError320::RosterMismatch)?;
    if endorser_signing_key.get_public_key().into_bytes() != roster_entry.signing_verification_key {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::EndorserSigningKeyMismatch {
                endorser_position,
            },
        );
    }
    let signature_randomness = Zeroizing::new(signature_randomness);
    if signature_randomness.iter().all(|byte| *byte == 0) {
        return Err(PseudorandomZeroSharingSeedReceiptTerminalError320::InvalidSignatureRandomness);
    }
    let signature = endorser_signing_key
        .try_sign_with_seed(
            &signature_randomness,
            &authorization_body.canonical_bytes()?,
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalError320::SignatureGenerationFailed {
                endorser_position,
            }
        })?;
    complete_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_signature_320(
        prepared_endorsement,
        roster,
        signature,
    )
}

pub(crate) fn prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_signature_320(
    prepared_endorsement: &PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320,
    roster: &Roster,
) -> Result<
    PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementAuthorizationBody320,
    PseudorandomZeroSharingSeedReceiptTerminalError320,
> {
    validate_prepared_terminal_endorsement(prepared_endorsement, roster)?;
    PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementAuthorizationBody320::new(
        prepared_endorsement.terminal_body,
        prepared_endorsement.endorser_position,
    )
}

pub(crate) fn complete_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_signature_320(
    prepared_endorsement: PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320,
    roster: &Roster,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
) -> Result<
    ProducedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320,
    PseudorandomZeroSharingSeedReceiptTerminalError320,
> {
    let authorization_body =
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_signature_320(
            &prepared_endorsement,
            roster,
        )?;
    let endorsement_envelope =
        PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320::new(
            authorization_body,
            signature,
        );
    let endorsement_envelope_bytes = endorsement_envelope.canonical_bytes()?;
    let decoded_endorsement =
        PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320::from_canonical_bytes(
            prepared_endorsement.terminal_body,
            &endorsement_envelope_bytes,
        )?;
    if decoded_endorsement != endorsement_envelope {
        return Err(terminal_object_mismatch("produced endorsement envelope"));
    }
    verify_terminal_endorsement_signature(
        prepared_endorsement.terminal_body,
        roster,
        &decoded_endorsement,
    )?;
    Ok(
        ProducedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320 {
            prepared_endorsement,
            endorsement_envelope,
            endorsement_envelope_bytes,
        },
    )
}

pub(crate) fn verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
    prepared_endorsement: &PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320,
    roster: &Roster,
    endorsement_envelope_bytes: &[u8],
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalError320> {
    validate_prepared_terminal_endorsement(prepared_endorsement, roster)?;
    let endorsement =
        PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320::from_canonical_bytes(
            prepared_endorsement.terminal_body,
            endorsement_envelope_bytes,
        )?;
    if endorsement.authorization_body().endorser_position()
        != prepared_endorsement.endorser_position
    {
        return Err(terminal_object_mismatch("endorser position"));
    }
    verify_terminal_endorsement_signature(prepared_endorsement.terminal_body, roster, &endorsement)
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320 {
    terminal_body: PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320,
    endorsement_envelopes:
        Box<[PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320]>,
}

impl PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320 {
    pub(crate) fn new(
        terminal_body: PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320,
        endorsement_envelopes: Vec<
            PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320,
        >,
    ) -> Result<Self, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        validate_endorsement_inventory(terminal_body, &endorsement_envelopes)?;
        Ok(Self {
            terminal_body,
            endorsement_envelopes: endorsement_envelopes.into_boxed_slice(),
        })
    }

    pub(crate) fn endorsement_envelopes(
        &self,
    ) -> &[PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320] {
        &self.endorsement_envelopes
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        let mut items = Vec::with_capacity(
            TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT + self.endorsement_envelopes.len(),
        );
        items.push(CanonicalItem::nonempty_ascii(
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_CERTIFICATE_DOMAIN,
        )?);
        items.push(CanonicalItem::variable_bytes(
            self.terminal_body.canonical_bytes()?,
        )?);
        for endorsement_envelope in &self.endorsement_envelopes {
            items.push(CanonicalItem::variable_bytes(
                endorsement_envelope.canonical_bytes()?,
            )?);
        }
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            items,
        )
        .encode()?)
    }

    pub(crate) fn identity(
        &self,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_CERTIFICATE_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    pub(crate) fn canonical_byte_length_for_participant_count(
        participant_count: u16,
    ) -> Result<usize, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        if derive_foundation_roster_parameters(participant_count).is_none() {
            return Err(PseudorandomZeroSharingSeedReceiptTerminalError320::GeometryMismatch);
        }
        let endorsement_count = usize::from(participant_count);
        CANONICAL_TUPLE_HEADER_BYTE_LENGTH
            .checked_add(
                TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT
                    .checked_add(endorsement_count)
                    .and_then(|item_count| {
                        item_count.checked_mul(CANONICAL_ITEM_HEADER_BYTE_LENGTH)
                    })
                    .ok_or(
                        PseudorandomZeroSharingSeedReceiptTerminalError320::ArithmeticOverflow,
                    )?,
            )
            .and_then(|length| {
                length.checked_add(CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH)
            })
            .and_then(|length| {
                length.checked_add(
                    PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_CERTIFICATE_DOMAIN
                        .len(),
                )
            })
            .and_then(|length| {
                length.checked_add(CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH)
            })
            .and_then(|length| {
                length.checked_add(
                    PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_BODY_BYTE_LENGTH,
                )
            })
            .and_then(|length| {
                CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH
                    .checked_add(
                        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH,
                    )
                    .and_then(|endorsement_length| {
                        endorsement_count.checked_mul(endorsement_length)
                    })
                    .and_then(|all_endorsement_length| {
                        length.checked_add(all_endorsement_length)
                    })
            })
            .ok_or(PseudorandomZeroSharingSeedReceiptTerminalError320::ArithmeticOverflow)
    }

    fn from_canonical_bytes(
        receipt_inventory: &VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320,
        bytes: &[u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        let expected_terminal_body =
            PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320::new(receipt_inventory)?;
        let tuple = CanonicalTuple::decode(bytes, &terminal_certificate_decode_limits())?;
        let expected_endorsement_count = usize::from(expected_terminal_body.participant_count());
        let expected_item_count = TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT
            .checked_add(expected_endorsement_count)
            .ok_or(PseudorandomZeroSharingSeedReceiptTerminalError320::ArithmeticOverflow)?;
        if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
            return Err(terminal_object_mismatch("schema identifier"));
        }
        if tuple.schema_version != CANONICAL_TUPLE_VERSION {
            return Err(terminal_object_mismatch("schema version"));
        }
        if tuple.items.len() != expected_item_count {
            return Err(
                PseudorandomZeroSharingSeedReceiptTerminalError320::EndorsementCount {
                    expected: expected_endorsement_count,
                    actual: tuple
                        .items
                        .len()
                        .saturating_sub(TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT),
                },
            );
        }
        require_ascii(
            &tuple.items[0],
            PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_CERTIFICATE_DOMAIN,
            "object domain",
        )?;
        if tuple.items[1].item_type() != CanonicalItemType::RawBytes {
            return Err(terminal_object_mismatch("terminal body"));
        }
        let terminal_body =
            PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320::from_canonical_bytes(
                receipt_inventory,
                tuple.items[1].variable_value_bytes()?,
            )?;
        let endorsement_envelopes = tuple.items[TERMINAL_CERTIFICATE_PREFIX_ITEM_COUNT..]
            .iter()
            .map(|item| {
                if item.item_type() != CanonicalItemType::RawBytes {
                    return Err(terminal_object_mismatch("endorsement envelope"));
                }
                PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320::from_canonical_bytes(
                    terminal_body,
                    item.variable_value_bytes()?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(terminal_body, endorsement_envelopes)
    }
}

impl fmt::Debug for PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320")
            .field("terminal_body", &self.terminal_body)
            .field("endorsement_count", &self.endorsement_envelopes.len())
            .field("endorsement_signatures", &"[redacted]")
            .finish()
    }
}

/// Complete receipt inventory after every roster participant endorsed the same
/// semantic inventory.
///
/// This establishes only a roster-wide common view of the receipt inventory.
/// A future local/global join may consume it after independently checking the
/// participant's retained authenticated receipt. It does not implement durable
/// endorsement locking, coin opening, burn state, seed combination, or
/// preparation-continuation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320 {
    root_terminal: RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    receipt_inventory: VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320,
    terminal_body: PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320,
    certificate_identity: Hash512,
}

impl RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320 {
    pub(crate) const fn root_terminal(
        &self,
    ) -> &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320 {
        &self.root_terminal
    }

    pub(crate) const fn receipt_inventory(
        &self,
    ) -> &VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320 {
        &self.receipt_inventory
    }

    pub(crate) const fn terminal_body(
        &self,
    ) -> PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320 {
        self.terminal_body
    }

    pub(crate) fn identity(
        &self,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedReceiptTerminalError320> {
        self.terminal_body.identity()
    }

    pub(crate) const fn certificate_identity(&self) -> Hash512 {
        self.certificate_identity
    }
}

pub(crate) fn verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
    root_terminal: RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    receipt_inventory: VerifiedPseudorandomZeroSharingSeedRecipientReceiptInventory320,
    roster: &Roster,
    terminal_certificate_bytes: &[u8],
) -> Result<
    RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320,
    PseudorandomZeroSharingSeedReceiptTerminalError320,
> {
    validate_roster(&root_terminal, roster)?;
    if receipt_inventory.body.root_terminal_identity != root_terminal.identity()? {
        return Err(terminal_object_mismatch("root-terminal identity"));
    }
    let terminal_body =
        PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320::new(&receipt_inventory)?;
    let terminal_certificate =
        PseudorandomZeroSharingSeedRecipientReceiptTerminalCertificate320::from_canonical_bytes(
            &receipt_inventory,
            terminal_certificate_bytes,
        )?;
    for endorsement_envelope in terminal_certificate.endorsement_envelopes() {
        verify_terminal_endorsement_signature(terminal_body, roster, endorsement_envelope)?;
    }
    Ok(
        RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320 {
            root_terminal,
            receipt_inventory,
            terminal_body,
            certificate_identity: terminal_certificate.identity()?,
        },
    )
}

fn validate_roster(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    roster: &Roster,
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalError320> {
    roster
        .validate()
        .map_err(|_| PseudorandomZeroSharingSeedReceiptTerminalError320::RosterMismatch)?;
    let participant_count = root_terminal.root_inventory().body().participant_count();
    let first_root = root_terminal
        .root_inventory()
        .root_body(0)
        .ok_or(PseudorandomZeroSharingSeedReceiptTerminalError320::RosterMismatch)?;
    if roster.entries.len() != usize::from(participant_count)
        || roster
            .roster_hash()
            .map_err(|_| PseudorandomZeroSharingSeedReceiptTerminalError320::RosterMismatch)?
            != first_root.layout().preparation_context().roster_hash()
    {
        return Err(PseudorandomZeroSharingSeedReceiptTerminalError320::RosterMismatch);
    }
    Ok(())
}

fn validate_prepared_terminal_endorsement(
    prepared_endorsement: &PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320,
    roster: &Roster,
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalError320> {
    validate_roster(&prepared_endorsement.root_terminal, roster)?;
    if prepared_endorsement
        .receipt_inventory
        .body
        .root_terminal_identity
        != prepared_endorsement.root_terminal.identity()?
    {
        return Err(terminal_object_mismatch("root-terminal identity"));
    }
    if PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320::new(
        &prepared_endorsement.receipt_inventory,
    )? != prepared_endorsement.terminal_body
    {
        return Err(terminal_object_mismatch("terminal body"));
    }
    validate_endorser_position(
        prepared_endorsement.terminal_body,
        prepared_endorsement.endorser_position,
    )
}

fn verify_terminal_endorsement_signature(
    terminal_body: PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320,
    roster: &Roster,
    endorsement_envelope: &PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320,
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalError320> {
    let authorization_body = endorsement_envelope.authorization_body();
    if authorization_body.terminal_body_identity != terminal_body.identity()? {
        return Err(terminal_object_mismatch("terminal-body identity"));
    }
    let endorser_position = authorization_body.endorser_position();
    validate_endorser_position(terminal_body, endorser_position)?;
    let roster_entry = roster.entries.get(usize::from(endorser_position)).ok_or(
        PseudorandomZeroSharingSeedReceiptTerminalError320::EndorserPositionOutOfRange {
            endorser_position,
            participant_count: terminal_body.participant_count(),
        },
    )?;
    if roster_entry.roster_position != endorser_position {
        return Err(PseudorandomZeroSharingSeedReceiptTerminalError320::RosterMismatch);
    }
    let public_key = ml_dsa_65::PublicKey::try_from_bytes(roster_entry.signing_verification_key)
        .map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalError320::MalformedSigningVerificationKey {
                endorser_position,
            }
        })?;
    if !public_key.verify(
        &authorization_body.canonical_bytes()?,
        &endorsement_envelope.signature,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT,
    ) {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::InvalidEndorsementSignature {
                endorser_position,
            },
        );
    }
    Ok(())
}

fn validate_endorsement_inventory(
    terminal_body: PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320,
    endorsement_envelopes: &[PseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsementEnvelope320],
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalError320> {
    let expected_endorsement_count = usize::from(terminal_body.participant_count());
    if endorsement_envelopes.len() != expected_endorsement_count {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::EndorsementCount {
                expected: expected_endorsement_count,
                actual: endorsement_envelopes.len(),
            },
        );
    }
    let expected_terminal_body_identity = terminal_body.identity()?;
    for (endorser_index, endorsement_envelope) in endorsement_envelopes.iter().enumerate() {
        let authorization_body = endorsement_envelope.authorization_body();
        if authorization_body.terminal_body_identity != expected_terminal_body_identity {
            return Err(terminal_object_mismatch("terminal-body identity"));
        }
        let expected_endorser_position = u16::try_from(endorser_index)
            .map_err(|_| PseudorandomZeroSharingSeedReceiptTerminalError320::ArithmeticOverflow)?;
        if authorization_body.endorser_position() != expected_endorser_position {
            return Err(PseudorandomZeroSharingSeedReceiptTerminalError320::EndorsementOrder);
        }
    }
    Ok(())
}

fn validate_endorser_position(
    terminal_body: PseudorandomZeroSharingSeedRecipientReceiptTerminalBody320,
    endorser_position: u16,
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalError320> {
    if endorser_position >= terminal_body.participant_count() {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalError320::EndorserPositionOutOfRange {
                endorser_position,
                participant_count: terminal_body.participant_count(),
            },
        );
    }
    Ok(())
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalError320> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
        return Err(terminal_object_mismatch("schema identifier"));
    }
    if tuple.schema_version != CANONICAL_TUPLE_VERSION {
        return Err(terminal_object_mismatch("schema version"));
    }
    if tuple.items.len() != expected_item_count {
        return Err(terminal_object_mismatch("item count"));
    }
    require_ascii(&tuple.items[0], expected_domain, "object domain")
}

fn require_ascii(
    item: &CanonicalItem,
    expected: &str,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalError320> {
    if item.item_type() != CanonicalItemType::Ascii
        || item.variable_value_bytes()? != expected.as_bytes()
    {
        return Err(terminal_object_mismatch(field));
    }
    Ok(())
}

fn require_hash512(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalError320> {
    if item.item_type() != CanonicalItemType::Hash512
        || item.canonical_bytes() != expected.as_bytes()
    {
        return Err(terminal_object_mismatch(field));
    }
    Ok(())
}

fn read_u16(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u16, PseudorandomZeroSharingSeedReceiptTerminalError320> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(terminal_object_mismatch(field));
    }
    let bytes: [u8; size_of::<u16>()] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| terminal_object_mismatch(field))?;
    Ok(u16::from_le_bytes(bytes))
}

const fn terminal_object_mismatch(
    field: &'static str,
) -> PseudorandomZeroSharingSeedReceiptTerminalError320 {
    PseudorandomZeroSharingSeedReceiptTerminalError320::ObjectMismatch { field }
}

fn terminal_control_object_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_TERMINAL_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_TERMINAL_CONTROL_OBJECT_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_TERMINAL_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 3,
        maximum_cumulative_work_byte_length: MAXIMUM_TERMINAL_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_TERMINAL_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}

fn terminal_certificate_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_TERMINAL_CONTROL_OBJECT_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_TERMINAL_CONTROL_OBJECT_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_TERMINAL_CONTROL_OBJECT_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 5,
        maximum_cumulative_work_byte_length: MAXIMUM_TERMINAL_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length:
            MAXIMUM_TERMINAL_CONTROL_OBJECT_CUMULATIVE_BYTE_LENGTH,
    }
}

const _: () = assert!(
    PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH
        > ML_DSA_65_SIGNATURE_BYTE_LENGTH
);
const _: () = assert!(ML_DSA_65_SIGNATURE_BYTE_LENGTH == ml_dsa_65::SIG_LEN);
