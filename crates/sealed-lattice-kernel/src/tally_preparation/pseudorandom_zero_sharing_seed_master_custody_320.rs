use core::fmt;

use zeroize::Zeroizing;

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalDecodeLimits,
    CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512, Roster,
};

use super::{
    TallyPreparationContext,
    pseudorandom_zero_sharing_pair_and_coin_seed_320::{
        COLLECTIVE_COIN_SOURCE_BYTE_LENGTH, COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_BYTE_LENGTH,
        CollectiveCoinSourceOpening320,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH,
        PseudorandomZeroSharingPairSeedOpening320,
        SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH,
    },
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogCoordinate320,
        PseudorandomZeroSharingSeedCatalogInclusionProof320,
        PseudorandomZeroSharingSeedCatalogLayout320,
    },
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320::{
        PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320,
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320,
    },
    pseudorandom_zero_sharing_seed_catalog_root_terminal_320::{
        RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
        verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320,
    },
    pseudorandom_zero_sharing_seed_delivery_320::{
        PseudorandomZeroSharingSeedDeliveryLayout320,
        PseudorandomZeroSharingSeedDeliveryVerifier320,
        derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320,
        verify_pseudorandom_zero_sharing_seed_recipient_inventory_320,
    },
    pseudorandom_zero_sharing_seed_master_join_320::{
        PSEUDORANDOM_ZERO_SHARING_JOINED_SEED_MASTER_CUSTODY_DOMAIN,
        PseudorandomZeroSharingLocalSeedCatalogEntryBytes320,
        join_pseudorandom_zero_sharing_seed_masters_320,
        verify_pseudorandom_zero_sharing_local_seed_catalog_320,
    },
    pseudorandom_zero_sharing_seed_receipt_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_BYTE_LENGTH,
        PseudorandomZeroSharingSeedRecipientReceiptBody320,
        pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_body_byte_length,
        restore_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_320,
    },
    pseudorandom_zero_sharing_seed_receipt_terminal_320::{
        RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_inventory_320,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320,
    },
    pseudorandom_zero_sharing_subset_seed_320::{
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH,
        PseudorandomZeroSharingSubsetSeedOpening320,
    },
};

const JOIN_REQUEST_MAGIC: &[u8; 4] = b"SLJQ";
const VERIFICATION_CONTEXT_MAGIC: &[u8; 4] = b"SLJV";
const SOURCE_CUSTODY_RECORD_MAGIC: &[u8; 4] = b"SLCS";
const RECEIPT_CUSTODY_RECORD_MAGIC: &[u8; 4] = b"SLRC";
const JOINED_CUSTODY_RECORD_MAGIC: &[u8; 4] = b"SLJM";
const RESPONSE_MAGIC: &[u8; 4] = b"SLJR";
const CODEC_VERSION: u16 = 1;
const COMPLETED_RECORD_KIND: u8 = 2;
const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const MAXIMUM_COPIED_BUFFER_BYTE_LENGTH: usize = 8 * 1024 * 1024;
const MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH: usize = 1024 * 1024;
const MAXIMUM_PREPARATION_CONTEXT_BYTE_LENGTH: usize = 4096;
const MAXIMUM_PARTICIPANT_COUNT: usize = 32;
const JOIN_RESPONSE_STATUS: u8 = 1;
const VALIDATION_RESPONSE_STATUS: u8 = 2;
const FAILURE_RESPONSE_STATUS: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedMasterCustodyError320 {
    MalformedRequest(&'static str),
    ResourceLimit(&'static str),
    ContextMismatch(&'static str),
    PublicVerification(&'static str),
    SourceCustody(&'static str),
    ReceiptCustody(&'static str),
    JoinedPayload(&'static str),
}

impl PseudorandomZeroSharingSeedMasterCustodyError320 {
    const fn response_code(&self) -> u16 {
        match self {
            Self::MalformedRequest(_) => 1,
            Self::ResourceLimit(_) => 2,
            Self::ContextMismatch(_) => 3,
            Self::PublicVerification(_) => 4,
            Self::SourceCustody(_) => 5,
            Self::ReceiptCustody(_) => 6,
            Self::JoinedPayload(_) => 7,
        }
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedMasterCustodyError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, field) = match self {
            Self::MalformedRequest(field) => ("malformed request", field),
            Self::ResourceLimit(field) => ("resource limit", field),
            Self::ContextMismatch(field) => ("context mismatch", field),
            Self::PublicVerification(field) => ("public verification", field),
            Self::SourceCustody(field) => ("source custody", field),
            Self::ReceiptCustody(field) => ("receipt custody", field),
            Self::JoinedPayload(field) => ("joined payload", field),
        };
        write!(formatter, "joined seed-master {kind}: {field}")
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedMasterCustodyError320 {}

#[derive(Clone, Copy)]
struct JoinedCustodyContext320 {
    parameter_identity: Hash512,
    roster_identity: Hash512,
    action_context_identity: Hash512,
    preparation_context_identity: Hash512,
    catalog_compiler_identity: Hash512,
    state_predecessor_identity: Hash512,
    root_terminal_identity: Hash512,
    root_terminal_certificate_identity: Hash512,
    receipt_terminal_identity: Hash512,
    receipt_terminal_certificate_identity: Hash512,
    authenticated_recipient_inventory_identity: Hash512,
    receipt_body_identity: Hash512,
    receipt_envelope_identity: Hash512,
    preparation_attempt_ordinal: u16,
    participant_count: u16,
    participant_position: u16,
}

#[derive(Clone, Copy)]
pub(super) struct SeedCatalogSourceCustodyContext320 {
    pub(super) parameter_identity: Hash512,
    pub(super) roster_identity: Hash512,
    pub(super) action_context_identity: Hash512,
    pub(super) preparation_context_identity: Hash512,
    pub(super) catalog_compiler_identity: Hash512,
    pub(super) state_predecessor_identity: Hash512,
    pub(super) preparation_attempt_ordinal: u16,
    pub(super) participant_count: u16,
    pub(super) participant_position: u16,
}

impl JoinedCustodyContext320 {
    const fn source_custody_context(self) -> SeedCatalogSourceCustodyContext320 {
        SeedCatalogSourceCustodyContext320 {
            parameter_identity: self.parameter_identity,
            roster_identity: self.roster_identity,
            action_context_identity: self.action_context_identity,
            preparation_context_identity: self.preparation_context_identity,
            catalog_compiler_identity: self.catalog_compiler_identity,
            state_predecessor_identity: self.state_predecessor_identity,
            preparation_attempt_ordinal: self.preparation_attempt_ordinal,
            participant_count: self.participant_count,
            participant_position: self.participant_position,
        }
    }

    const fn receipt_custody_context(self) -> SeedRecipientReceiptCustodyContext320 {
        SeedRecipientReceiptCustodyContext320 {
            parameter_identity: self.parameter_identity,
            preparation_context_identity: self.preparation_context_identity,
            root_terminal_identity: self.root_terminal_identity,
            preparation_attempt_ordinal: self.preparation_attempt_ordinal,
            participant_count: self.participant_count,
            recipient_position: self.participant_position,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct SeedRecipientReceiptCustodyContext320 {
    pub(super) parameter_identity: Hash512,
    pub(super) preparation_context_identity: Hash512,
    pub(super) root_terminal_identity: Hash512,
    pub(super) preparation_attempt_ordinal: u16,
    pub(super) participant_count: u16,
    pub(super) recipient_position: u16,
}

pub(super) struct VerifiedSeedRecipientReceiptCustody320 {
    pub(super) authenticated_inventory_identity: Hash512,
    pub(super) receipt: super::pseudorandom_zero_sharing_seed_receipt_320::RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
    pub(super) receipt_body_identity: Hash512,
    pub(super) receipt_envelope_identity: Hash512,
}

struct JoinRequest320<'a> {
    context: JoinedCustodyContext320,
    source_custody_record_bytes: &'a [u8],
    receipt_custody_record_bytes: &'a [u8],
    verification_context_bytes: &'a [u8],
    root_terminal_certificate_bytes: &'a [u8],
    receipt_terminal_certificate_bytes: &'a [u8],
}

struct VerificationContext320<'a> {
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    roster: Roster,
    root_packages: Vec<PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320<'a>>,
    receipt_envelope_bytes: Vec<&'a [u8]>,
}

struct SourceLeafBytes320<'a> {
    contribution: &'a [u8],
    commitment_salt: &'a [u8],
}

struct LocalCatalogEntryBytes320<'a> {
    opening_bytes: &'a [u8],
    inclusion_proof_bytes: &'a [u8],
}

struct SourceCustodyRecord320<'a> {
    entries: Vec<LocalCatalogEntryBytes320<'a>>,
    delivery_source_payloads: Vec<&'a [u8]>,
    source_inventory: Vec<SourceLeafBytes320<'a>>,
}

struct ParsedSourceCustodyRecord320<'a> {
    delivery_source_payloads: Vec<&'a [u8]>,
    local_catalog: super::pseudorandom_zero_sharing_seed_master_join_320::RootTerminalMatchedPseudorandomZeroSharingLocalSeedCatalog320,
    recipient_positions: Vec<u16>,
}

pub(super) struct VerifiedSeedCatalogDeliverySources320 {
    payloads: Vec<Zeroizing<Vec<u8>>>,
    recipient_positions: Vec<u16>,
}

impl VerifiedSeedCatalogDeliverySources320 {
    pub(super) fn payload_for_recipient(&self, recipient_position: u16) -> Option<&[u8]> {
        self.recipient_positions
            .iter()
            .position(|position| *position == recipient_position)
            .and_then(|delivery_index| self.payloads.get(delivery_index))
            .map(|payload| payload.as_slice())
    }
}

struct ReceiptCustodyRecord320<'a> {
    authenticated_inventory_body_bytes: &'a [u8],
    receipt_intent_bytes: &'a [u8],
    local_seed_custody_segments: Vec<&'a [u8]>,
    receipt_envelope_bytes: &'a [u8],
}

struct BoundedCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BoundedCursor<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, PseudorandomZeroSharingSeedMasterCustodyError320> {
        if bytes.len() > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
            return Err(
                PseudorandomZeroSharingSeedMasterCustodyError320::ResourceLimit(
                    "input byte length",
                ),
            );
        }
        Ok(Self { bytes, offset: 0 })
    }

    fn read_exact(
        &mut self,
        byte_length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], PseudorandomZeroSharingSeedMasterCustodyError320> {
        let end = self
            .offset
            .checked_add(byte_length)
            .ok_or(PseudorandomZeroSharingSeedMasterCustodyError320::ResourceLimit(field))?;
        if end > self.bytes.len() {
            return Err(PseudorandomZeroSharingSeedMasterCustodyError320::MalformedRequest(field));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_unsigned8(
        &mut self,
        field: &'static str,
    ) -> Result<u8, PseudorandomZeroSharingSeedMasterCustodyError320> {
        Ok(self.read_exact(1, field)?[0])
    }

    fn read_unsigned16(
        &mut self,
        field: &'static str,
    ) -> Result<u16, PseudorandomZeroSharingSeedMasterCustodyError320> {
        Ok(u16::from_le_bytes(
            self.read_exact(size_of::<u16>(), field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMasterCustodyError320::MalformedRequest(field)
                })?,
        ))
    }

    fn read_unsigned32(
        &mut self,
        field: &'static str,
    ) -> Result<usize, PseudorandomZeroSharingSeedMasterCustodyError320> {
        let value = u32::from_le_bytes(
            self.read_exact(size_of::<u32>(), field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMasterCustodyError320::MalformedRequest(field)
                })?,
        );
        usize::try_from(value)
            .map_err(|_| PseudorandomZeroSharingSeedMasterCustodyError320::ResourceLimit(field))
    }

    fn read_hash512(
        &mut self,
        field: &'static str,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedMasterCustodyError320> {
        Ok(Hash512::from_bytes(
            self.read_exact(Hash512::BYTE_LENGTH, field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMasterCustodyError320::MalformedRequest(field)
                })?,
        ))
    }

    fn read_bounded_bytes(
        &mut self,
        maximum_byte_length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], PseudorandomZeroSharingSeedMasterCustodyError320> {
        let byte_length = self.read_unsigned32(field)?;
        if byte_length == 0 || byte_length > maximum_byte_length {
            return Err(PseudorandomZeroSharingSeedMasterCustodyError320::ResourceLimit(field));
        }
        self.read_exact(byte_length, field)
    }

    fn require_magic(
        &mut self,
        expected: &[u8; 4],
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
        if self.read_exact(expected.len(), field)? != expected {
            return Err(PseudorandomZeroSharingSeedMasterCustodyError320::MalformedRequest(field));
        }
        Ok(())
    }

    fn require_version(
        &mut self,
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
        if self.read_unsigned16(field)? != CODEC_VERSION {
            return Err(PseudorandomZeroSharingSeedMasterCustodyError320::MalformedRequest(field));
        }
        Ok(())
    }

    fn require_complete(
        &self,
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
        if self.offset != self.bytes.len() {
            return Err(PseudorandomZeroSharingSeedMasterCustodyError320::MalformedRequest(field));
        }
        Ok(())
    }
}

fn read_joined_context(
    cursor: &mut BoundedCursor<'_>,
) -> Result<JoinedCustodyContext320, PseudorandomZeroSharingSeedMasterCustodyError320> {
    Ok(JoinedCustodyContext320 {
        parameter_identity: cursor.read_hash512("parameter identity")?,
        roster_identity: cursor.read_hash512("roster identity")?,
        action_context_identity: cursor.read_hash512("action-context identity")?,
        preparation_context_identity: cursor.read_hash512("preparation-context identity")?,
        catalog_compiler_identity: cursor.read_hash512("catalog-compiler identity")?,
        state_predecessor_identity: cursor.read_hash512("state-predecessor identity")?,
        root_terminal_identity: cursor.read_hash512("root-terminal identity")?,
        root_terminal_certificate_identity: cursor
            .read_hash512("root-terminal certificate identity")?,
        receipt_terminal_identity: cursor.read_hash512("receipt-terminal identity")?,
        receipt_terminal_certificate_identity: cursor
            .read_hash512("receipt-terminal certificate identity")?,
        authenticated_recipient_inventory_identity: cursor
            .read_hash512("authenticated recipient-inventory identity")?,
        receipt_body_identity: cursor.read_hash512("receipt-body identity")?,
        receipt_envelope_identity: cursor.read_hash512("receipt-envelope identity")?,
        preparation_attempt_ordinal: cursor.read_unsigned16("preparation-attempt ordinal")?,
        participant_count: cursor.read_unsigned16("participant count")?,
        participant_position: cursor.read_unsigned16("participant position")?,
    })
}

fn parse_join_request(
    bytes: &[u8],
) -> Result<JoinRequest320<'_>, PseudorandomZeroSharingSeedMasterCustodyError320> {
    let mut cursor = BoundedCursor::new(bytes)?;
    cursor.require_magic(JOIN_REQUEST_MAGIC, "join-request magic")?;
    cursor.require_version("join-request version")?;
    let context = read_joined_context(&mut cursor)?;
    let source_custody_record_bytes =
        cursor.read_bounded_bytes(MAXIMUM_COPIED_BUFFER_BYTE_LENGTH, "source-custody record")?;
    let receipt_custody_record_bytes =
        cursor.read_bounded_bytes(MAXIMUM_COPIED_BUFFER_BYTE_LENGTH, "receipt-custody record")?;
    let verification_context_bytes =
        cursor.read_bounded_bytes(MAXIMUM_COPIED_BUFFER_BYTE_LENGTH, "verification context")?;
    let root_terminal_certificate_bytes = cursor.read_bounded_bytes(
        MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
        "root-terminal certificate",
    )?;
    let receipt_terminal_certificate_bytes = cursor.read_bounded_bytes(
        MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
        "receipt-terminal certificate",
    )?;
    cursor.require_complete("join-request trailing bytes")?;
    Ok(JoinRequest320 {
        context,
        source_custody_record_bytes,
        receipt_custody_record_bytes,
        verification_context_bytes,
        root_terminal_certificate_bytes,
        receipt_terminal_certificate_bytes,
    })
}

fn parse_verification_context(
    bytes: &[u8],
) -> Result<VerificationContext320<'_>, PseudorandomZeroSharingSeedMasterCustodyError320> {
    let mut cursor = BoundedCursor::new(bytes)?;
    cursor.require_magic(VERIFICATION_CONTEXT_MAGIC, "verification-context magic")?;
    cursor.require_version("verification-context version")?;
    let parameter_identity = cursor.read_hash512("verification parameter identity")?;
    let preparation_context_bytes = cursor.read_bounded_bytes(
        MAXIMUM_PREPARATION_CONTEXT_BYTE_LENGTH,
        "preparation context",
    )?;
    let preparation_context =
        TallyPreparationContext::from_canonical_bytes(preparation_context_bytes).map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification(
                "preparation context",
            )
        })?;
    let roster_bytes = cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "roster")?;
    let roster = Roster::decode(roster_bytes, &CanonicalDecodeLimits::default()).map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification("roster")
    })?;
    if roster.encode().map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification("roster")
    })? != roster_bytes
    {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification(
                "noncanonical roster",
            ),
        );
    }
    let root_package_count = usize::from(cursor.read_unsigned16("root-package count")?);
    let expected_count = usize::from(preparation_context.participant_count());
    if root_package_count != expected_count || root_package_count > MAXIMUM_PARTICIPANT_COUNT {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification(
                "root-package count",
            ),
        );
    }
    let mut root_packages = Vec::with_capacity(root_package_count);
    for _ in 0..root_package_count {
        root_packages.push(
            PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320::new(
                cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "root body")?,
                cursor.read_bounded_bytes(
                    MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
                    "root reservation certificate",
                )?,
                cursor.read_bounded_bytes(
                    MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
                    "root output certificate",
                )?,
                cursor.read_bounded_bytes(
                    MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
                    "root signature envelope",
                )?,
            ),
        );
    }
    let receipt_count = usize::from(cursor.read_unsigned16("receipt-envelope count")?);
    if receipt_count != expected_count {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification(
                "receipt-envelope count",
            ),
        );
    }
    let mut receipt_envelope_bytes = Vec::with_capacity(receipt_count);
    for _ in 0..receipt_count {
        receipt_envelope_bytes.push(
            cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "receipt envelope")?,
        );
    }
    cursor.require_complete("verification-context trailing bytes")?;
    Ok(VerificationContext320 {
        parameter_identity,
        preparation_context,
        roster,
        root_packages,
        receipt_envelope_bytes,
    })
}

fn verify_public_context(
    request: &JoinRequest320<'_>,
    verification: VerificationContext320<'_>,
) -> Result<
    (
        RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320,
        Roster,
        TallyPreparationContext,
    ),
    PseudorandomZeroSharingSeedMasterCustodyError320,
> {
    let context = request.context;
    let preparation_context = verification.preparation_context;
    require_context_match(
        context.parameter_identity == verification.parameter_identity,
        "parameter identity",
    )?;
    require_context_match(
        context.preparation_context_identity == preparation_context.identity(),
        "preparation-context identity",
    )?;
    require_context_match(
        context.action_context_identity == preparation_context.action_context_hash(),
        "action-context identity",
    )?;
    require_context_match(
        context.preparation_attempt_ordinal == PREPARATION_ATTEMPT_ORDINAL,
        "preparation-attempt ordinal",
    )?;
    require_context_match(
        context.participant_count == preparation_context.participant_count()
            && context.participant_position < context.participant_count,
        "participant coordinates",
    )?;
    let roster_identity = verification.roster.roster_hash().map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification("roster identity")
    })?;
    require_context_match(
        context.roster_identity == roster_identity
            && preparation_context.roster_hash() == roster_identity,
        "roster identity",
    )?;
    let local_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        verification.parameter_identity,
        preparation_context,
        context.participant_position,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification("local catalog layout")
    })?;
    require_context_match(
        context.catalog_compiler_identity == local_layout.compiler_identity(),
        "catalog-compiler identity",
    )?;

    let root_inventory = verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
        verification.parameter_identity,
        preparation_context,
        &verification.roster,
        &verification.root_packages,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification("root inventory")
    })?;
    let root_terminal = verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
        root_inventory,
        &verification.roster,
        request.root_terminal_certificate_bytes,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification("root terminal")
    })?;
    require_context_match(
        root_terminal.identity().map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification(
                "root-terminal identity",
            )
        })? == context.root_terminal_identity
            && root_terminal.certificate_identity() == context.root_terminal_certificate_identity,
        "root-terminal identities",
    )?;
    let receipt_inventory = verify_pseudorandom_zero_sharing_seed_recipient_receipt_inventory_320(
        &root_terminal,
        &verification.roster,
        &verification.receipt_envelope_bytes,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification("receipt inventory")
    })?;
    let receipt_terminal = verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
        root_terminal,
        receipt_inventory,
        &verification.roster,
        request.receipt_terminal_certificate_bytes,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification("receipt terminal")
    })?;
    require_context_match(
        receipt_terminal.identity().map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::PublicVerification(
                "receipt-terminal identity",
            )
        })? == context.receipt_terminal_identity
            && receipt_terminal.certificate_identity()
                == context.receipt_terminal_certificate_identity,
        "receipt-terminal identities",
    )?;
    Ok((receipt_terminal, verification.roster, preparation_context))
}

fn parse_and_verify_source_custody_record<'a>(
    bytes: &'a [u8],
    context: SeedCatalogSourceCustodyContext320,
    preparation_context: TallyPreparationContext,
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
) -> Result<ParsedSourceCustodyRecord320<'a>, PseudorandomZeroSharingSeedMasterCustodyError320> {
    let mut cursor = BoundedCursor::new(bytes)?;
    cursor.require_magic(SOURCE_CUSTODY_RECORD_MAGIC, "source-custody magic")?;
    cursor.require_version("source-custody version")?;
    if cursor.read_unsigned8("source-custody record kind")? != COMPLETED_RECORD_KIND {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
                "record is not complete",
            ),
        );
    }
    require_source_context_hash(
        cursor.read_hash512("source parameter identity")?,
        context.parameter_identity,
        "parameter identity",
    )?;
    require_source_context_hash(
        cursor.read_hash512("source roster identity")?,
        context.roster_identity,
        "roster identity",
    )?;
    require_source_context_hash(
        cursor.read_hash512("source action identity")?,
        context.action_context_identity,
        "action-context identity",
    )?;
    require_source_context_hash(
        cursor.read_hash512("source preparation identity")?,
        context.preparation_context_identity,
        "preparation-context identity",
    )?;
    require_source_context_hash(
        cursor.read_hash512("source compiler identity")?,
        context.catalog_compiler_identity,
        "catalog-compiler identity",
    )?;
    require_source_context_hash(
        cursor.read_hash512("source predecessor identity")?,
        context.state_predecessor_identity,
        "state-predecessor identity",
    )?;
    require_source_coordinate(
        cursor.read_unsigned16("source preparation attempt")?
            == context.preparation_attempt_ordinal,
        "preparation-attempt ordinal",
    )?;
    require_source_coordinate(
        cursor.read_unsigned16("source participant count")? == context.participant_count,
        "participant count",
    )?;
    require_source_coordinate(
        cursor.read_unsigned16("source participant position")? == context.participant_position,
        "participant position",
    )?;

    require_source_context_hash(
        context.roster_identity,
        preparation_context.roster_hash(),
        "preparation roster identity",
    )?;
    require_source_context_hash(
        context.action_context_identity,
        preparation_context.action_context_hash(),
        "preparation action-context identity",
    )?;
    require_source_context_hash(
        context.preparation_context_identity,
        preparation_context.identity(),
        "preparation identity",
    )?;
    require_source_coordinate(
        context.preparation_attempt_ordinal == PREPARATION_ATTEMPT_ORDINAL,
        "admitted preparation-attempt ordinal",
    )?;
    require_source_coordinate(
        context.participant_count == preparation_context.participant_count()
            && context.participant_position < context.participant_count,
        "preparation participant coordinates",
    )?;

    let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        context.parameter_identity,
        preparation_context,
        context.participant_position,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody("catalog layout")
    })?;
    require_source_context_hash(
        context.catalog_compiler_identity,
        layout.compiler_identity(),
        "derived catalog-compiler identity",
    )?;
    let selected_root_body = root_terminal
        .root_inventory()
        .root_body(context.participant_position)
        .ok_or(
            PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody("selected root body"),
        )?;
    if selected_root_body.layout() != layout {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
                "selected catalog layout",
            ),
        );
    }
    let expected_root_body_bytes = selected_root_body.canonical_bytes().map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody("root-body encoding")
    })?;
    let expected_leaf_count = usize::try_from(layout.leaf_count()).map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::ResourceLimit("catalog leaf count")
    })?;
    let expected_proof_byte_length =
        PseudorandomZeroSharingSeedCatalogInclusionProof320::canonical_byte_length_for_layout(
            layout,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
                "inclusion-proof geometry",
            )
        })?;
    let expected_delivery_count = usize::from(context.participant_count - 1);
    require_source_geometry(
        cursor.read_unsigned32("source leaf count")? == expected_leaf_count,
        "leaf count",
    )?;
    require_source_geometry(
        cursor.read_unsigned32("source contribution byte length")?
            == PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        "source-contribution byte length",
    )?;
    require_source_geometry(
        cursor.read_unsigned32("source salt byte length")?
            == PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH
            && PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH
                == SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH,
        "commitment-salt byte length",
    )?;
    require_source_geometry(
        cursor.read_unsigned32("source root-body byte length")? == expected_root_body_bytes.len(),
        "root-body byte length",
    )?;
    require_source_geometry(
        cursor.read_unsigned32("source inclusion-proof byte length")? == expected_proof_byte_length,
        "inclusion-proof byte length",
    )?;
    require_source_geometry(
        usize::from(cursor.read_unsigned16("source delivery count")?) == expected_delivery_count,
        "delivery count",
    )?;

    let coordinates = layout
        .coordinates()
        .map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody("catalog coordinates")
        })?
        .collect::<Vec<_>>();
    for coordinate in &coordinates {
        require_source_geometry(
            cursor.read_unsigned32("source opening byte length")?
                == opening_byte_length(*coordinate),
            "opening byte-length table",
        )?;
    }
    let recipient_positions = (0..context.participant_count)
        .filter(|position| *position != context.participant_position)
        .collect::<Vec<_>>();
    let mut delivery_source_byte_lengths = Vec::with_capacity(expected_delivery_count);
    for recipient_position in &recipient_positions {
        let byte_length =
            PseudorandomZeroSharingSeedDeliveryLayout320::derive(layout, *recipient_position)
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
                        "delivery-source geometry",
                    )
                })?
                .payload_byte_length();
        require_source_geometry(
            cursor.read_unsigned32("source delivery byte length")? == byte_length,
            "delivery-source byte-length table",
        )?;
        delivery_source_byte_lengths.push(byte_length);
    }

    let mut source_inventory = Vec::with_capacity(expected_leaf_count);
    for _ in 0..expected_leaf_count {
        source_inventory.push(SourceLeafBytes320 {
            contribution: cursor.read_exact(
                PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
                "source contribution",
            )?,
            commitment_salt: cursor.read_exact(
                PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
                "commitment salt",
            )?,
        });
    }
    require_source_context_hash(
        cursor.read_hash512("source catalog identity")?,
        layout.identity(),
        "catalog identity",
    )?;
    let root_body_bytes = cursor.read_exact(expected_root_body_bytes.len(), "source root body")?;
    if root_body_bytes != expected_root_body_bytes {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody("root-body bytes"),
        );
    }
    let mut entries = Vec::with_capacity(expected_leaf_count);
    for coordinate in &coordinates {
        entries.push(LocalCatalogEntryBytes320 {
            opening_bytes: cursor.read_exact(opening_byte_length(*coordinate), "source opening")?,
            inclusion_proof_bytes: cursor
                .read_exact(expected_proof_byte_length, "source inclusion proof")?,
        });
    }
    require_source_geometry(
        usize::from(cursor.read_unsigned16("retained delivery count")?) == expected_delivery_count,
        "retained delivery count",
    )?;
    let mut delivery_source_payloads = Vec::with_capacity(expected_delivery_count);
    for byte_length in delivery_source_byte_lengths {
        delivery_source_payloads.push(cursor.read_exact(byte_length, "delivery-source payload")?);
    }
    cursor.require_complete("source-custody trailing bytes")?;
    let source_record = SourceCustodyRecord320 {
        entries,
        delivery_source_payloads,
        source_inventory,
    };
    verify_source_inventory_matches_openings(&coordinates, &source_record)?;
    verify_delivery_sources(layout, &recipient_positions, &source_record)?;
    let local_entries = source_record
        .entries
        .iter()
        .map(|entry| {
            PseudorandomZeroSharingLocalSeedCatalogEntryBytes320::new(
                entry.opening_bytes,
                entry.inclusion_proof_bytes,
            )
        })
        .collect::<Vec<_>>();
    let local_catalog = verify_pseudorandom_zero_sharing_local_seed_catalog_320(
        root_terminal,
        context.participant_position,
        &local_entries,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
            "local catalog verification",
        )
    })?;
    Ok(ParsedSourceCustodyRecord320 {
        delivery_source_payloads: source_record.delivery_source_payloads,
        local_catalog,
        recipient_positions,
    })
}

fn parse_and_verify_source_custody(
    bytes: &[u8],
    context: JoinedCustodyContext320,
    preparation_context: TallyPreparationContext,
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
) -> Result<
    super::pseudorandom_zero_sharing_seed_master_join_320::RootTerminalMatchedPseudorandomZeroSharingLocalSeedCatalog320,
    PseudorandomZeroSharingSeedMasterCustodyError320,
>{
    Ok(parse_and_verify_source_custody_record(
        bytes,
        context.source_custody_context(),
        preparation_context,
        root_terminal,
    )?
    .local_catalog)
}

pub(super) fn verify_and_retain_seed_catalog_delivery_sources_320(
    bytes: &[u8],
    context: SeedCatalogSourceCustodyContext320,
    preparation_context: TallyPreparationContext,
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
) -> Result<VerifiedSeedCatalogDeliverySources320, PseudorandomZeroSharingSeedMasterCustodyError320>
{
    let parsed =
        parse_and_verify_source_custody_record(bytes, context, preparation_context, root_terminal)?;
    let payloads = parsed
        .delivery_source_payloads
        .into_iter()
        .map(|payload| Zeroizing::new(payload.to_vec()))
        .collect();
    Ok(VerifiedSeedCatalogDeliverySources320 {
        payloads,
        recipient_positions: parsed.recipient_positions,
    })
}

fn verify_source_inventory_matches_openings(
    coordinates: &[PseudorandomZeroSharingSeedCatalogCoordinate320],
    record: &SourceCustodyRecord320<'_>,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    if coordinates.len() != record.entries.len()
        || coordinates.len() != record.source_inventory.len()
    {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
                "source inventory count",
            ),
        );
    }
    for ((coordinate, entry), source_leaf) in coordinates
        .iter()
        .zip(&record.entries)
        .zip(&record.source_inventory)
    {
        let matches = match coordinate {
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(_) => {
                PseudorandomZeroSharingSubsetSeedOpening320::from_canonical_bytes(
                    entry.opening_bytes,
                )
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
                        "subset opening",
                    )
                })?
                .matches_retained_secret_material(
                    source_leaf.contribution,
                    source_leaf.commitment_salt,
                )
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::Pair { .. } => {
                PseudorandomZeroSharingPairSeedOpening320::from_canonical_bytes(entry.opening_bytes)
                    .map_err(|_| {
                        PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
                            "pair opening",
                        )
                    })?
                    .matches_retained_secret_material(
                        source_leaf.contribution,
                        source_leaf.commitment_salt,
                    )
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin => {
                CollectiveCoinSourceOpening320::from_canonical_bytes(entry.opening_bytes)
                    .map_err(|_| {
                        PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
                            "collective-coin opening",
                        )
                    })?
                    .matches_retained_secret_material(
                        source_leaf.contribution,
                        source_leaf.commitment_salt,
                    )
            }
        };
        if !matches {
            return Err(
                PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
                    "source inventory opening correspondence",
                ),
            );
        }
    }
    Ok(())
}

fn verify_delivery_sources(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    recipient_positions: &[u16],
    record: &SourceCustodyRecord320<'_>,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    if recipient_positions.len() != record.delivery_source_payloads.len() {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
                "delivery-source count",
            ),
        );
    }
    for (recipient_position, payload_bytes) in recipient_positions
        .iter()
        .copied()
        .zip(&record.delivery_source_payloads)
    {
        let delivery_layout =
            PseudorandomZeroSharingSeedDeliveryLayout320::derive(layout, recipient_position)
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
                        "delivery-source layout",
                    )
                })?;
        let mut payload_cursor = BoundedCursor::new(payload_bytes)?;
        for subset in delivery_layout.subsets() {
            require_delivery_source_entry(
                &mut payload_cursor,
                layout,
                PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(*subset),
                record,
            )?;
        }
        require_delivery_source_entry(
            &mut payload_cursor,
            layout,
            layout.pair_coordinate(recipient_position).map_err(|_| {
                PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
                    "delivery-source pair coordinate",
                )
            })?,
            record,
        )?;
        payload_cursor.require_complete("delivery-source trailing bytes")?;
    }
    Ok(())
}

fn require_delivery_source_entry(
    cursor: &mut BoundedCursor<'_>,
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    coordinate: PseudorandomZeroSharingSeedCatalogCoordinate320,
    record: &SourceCustodyRecord320<'_>,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    let leaf_ordinal = usize::try_from(layout.leaf_ordinal(coordinate).map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
            "delivery-source leaf ordinal",
        )
    })?)
    .map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::ResourceLimit(
            "delivery-source leaf ordinal",
        )
    })?;
    let expected_entry = record.entries.get(leaf_ordinal).ok_or(
        PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody("delivery-source entry"),
    )?;
    if cursor.read_exact(expected_entry.opening_bytes.len(), "delivery opening")?
        != expected_entry.opening_bytes
        || cursor.read_exact(
            expected_entry.inclusion_proof_bytes.len(),
            "delivery inclusion proof",
        )? != expected_entry.inclusion_proof_bytes
    {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(
                "delivery-source byte correspondence",
            ),
        );
    }
    Ok(())
}

fn parse_and_verify_receipt_custody_record(
    bytes: &[u8],
    context: SeedRecipientReceiptCustodyContext320,
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    roster: &Roster,
) -> Result<VerifiedSeedRecipientReceiptCustody320, PseudorandomZeroSharingSeedMasterCustodyError320>
{
    let root_inventory_body = root_terminal.root_inventory().body();
    require_receipt_context_hash(
        context.parameter_identity,
        root_inventory_body.parameter_identity(),
        "terminal parameter identity",
    )?;
    require_receipt_context_hash(
        context.preparation_context_identity,
        root_inventory_body.preparation_context_identity(),
        "terminal preparation-context identity",
    )?;
    require_receipt_context_hash(
        context.root_terminal_identity,
        root_terminal.identity().map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody(
                "root-terminal identity",
            )
        })?,
        "verified root-terminal identity",
    )?;
    require_receipt_coordinate(
        context.preparation_attempt_ordinal == PREPARATION_ATTEMPT_ORDINAL,
        "admitted preparation-attempt ordinal",
    )?;
    require_receipt_coordinate(
        context.participant_count == root_inventory_body.participant_count()
            && context.recipient_position < context.participant_count,
        "terminal participant coordinates",
    )?;
    let mut cursor = BoundedCursor::new(bytes)?;
    cursor.require_magic(RECEIPT_CUSTODY_RECORD_MAGIC, "receipt-custody magic")?;
    cursor.require_version("receipt-custody version")?;
    if cursor.read_unsigned8("receipt-custody record kind")? != COMPLETED_RECORD_KIND {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody(
                "record is not complete",
            ),
        );
    }
    require_receipt_context_hash(
        cursor.read_hash512("receipt parameter identity")?,
        context.parameter_identity,
        "parameter identity",
    )?;
    require_receipt_context_hash(
        cursor.read_hash512("receipt preparation identity")?,
        context.preparation_context_identity,
        "preparation-context identity",
    )?;
    require_receipt_context_hash(
        cursor.read_hash512("receipt root-terminal identity")?,
        context.root_terminal_identity,
        "root-terminal identity",
    )?;
    require_receipt_coordinate(
        cursor.read_unsigned16("receipt preparation attempt")?
            == context.preparation_attempt_ordinal,
        "preparation-attempt ordinal",
    )?;
    require_receipt_coordinate(
        cursor.read_unsigned16("receipt participant count")? == context.participant_count,
        "participant count",
    )?;
    require_receipt_coordinate(
        cursor.read_unsigned16("receipt recipient position")? == context.recipient_position,
        "recipient position",
    )?;
    let stored_authenticated_inventory_identity =
        cursor.read_hash512("stored authenticated-inventory identity")?;
    let stored_receipt_intent_identity = cursor.read_hash512("stored receipt-intent identity")?;
    let expected_authenticated_inventory_body_byte_length =
        pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_body_byte_length(
            context.participant_count,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody(
                "authenticated-inventory geometry",
            )
        })?;
    require_receipt_geometry(
        cursor.read_unsigned32("authenticated-inventory body byte length")?
            == expected_authenticated_inventory_body_byte_length,
        "authenticated-inventory body byte length",
    )?;
    require_receipt_geometry(
        cursor.read_unsigned32("receipt-intent byte length")?
            == PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_BYTE_LENGTH,
        "receipt-intent byte length",
    )?;
    let expected_segment_count = usize::from(context.participant_count - 1);
    require_receipt_geometry(
        usize::from(cursor.read_unsigned16("receipt segment count")?) == expected_segment_count,
        "local seed-custody segment count",
    )?;
    let sender_positions = (0..context.participant_count)
        .filter(|position| *position != context.recipient_position)
        .collect::<Vec<_>>();
    let mut segment_byte_lengths = Vec::with_capacity(expected_segment_count);
    for sender_position in &sender_positions {
        let sender_layout = root_terminal
            .root_inventory()
            .root_body(*sender_position)
            .ok_or(
                PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody(
                    "sender root body",
                ),
            )?
            .layout();
        let expected_byte_length = PseudorandomZeroSharingSeedDeliveryLayout320::derive(
            sender_layout,
            context.recipient_position,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody(
                "local segment geometry",
            )
        })?
        .payload_byte_length();
        require_receipt_geometry(
            cursor.read_unsigned32("local segment byte length")? == expected_byte_length,
            "local segment byte-length table",
        )?;
        segment_byte_lengths.push(expected_byte_length);
    }
    let authenticated_inventory_body_bytes = cursor.read_exact(
        expected_authenticated_inventory_body_byte_length,
        "authenticated-inventory body",
    )?;
    let receipt_intent_bytes = cursor.read_exact(
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_BYTE_LENGTH,
        "receipt intent",
    )?;
    let mut local_seed_custody_segments = Vec::with_capacity(expected_segment_count);
    for byte_length in segment_byte_lengths {
        local_seed_custody_segments.push(cursor.read_exact(byte_length, "local seed segment")?);
    }
    require_receipt_geometry(
        cursor.read_unsigned32("receipt-envelope byte length")?
            == PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_BYTE_LENGTH,
        "receipt-envelope byte length",
    )?;
    let receipt_envelope_bytes = cursor.read_exact(
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_BYTE_LENGTH,
        "receipt envelope",
    )?;
    cursor.require_complete("receipt-custody trailing bytes")?;
    let receipt_record = ReceiptCustodyRecord320 {
        authenticated_inventory_body_bytes,
        receipt_intent_bytes,
        local_seed_custody_segments,
        receipt_envelope_bytes,
    };

    let root_matched_inventory = verify_retained_delivery_segments(
        root_terminal,
        context.recipient_position,
        &sender_positions,
        &receipt_record.local_seed_custody_segments,
    )?;
    let authenticated_inventory =
        restore_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            root_matched_inventory,
            receipt_record.authenticated_inventory_body_bytes,
            &receipt_record.local_seed_custody_segments,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody(
                "authenticated inventory restoration",
            )
        })?;
    let authenticated_inventory_identity =
        authenticated_inventory.body().identity().map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody(
                "authenticated-inventory identity",
            )
        })?;
    require_receipt_context_hash(
        stored_authenticated_inventory_identity,
        authenticated_inventory_identity,
        "stored authenticated-inventory identity",
    )?;
    let expected_receipt_body =
        PseudorandomZeroSharingSeedRecipientReceiptBody320::new(&authenticated_inventory).map_err(
            |_| PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody("receipt body"),
        )?;
    if expected_receipt_body.canonical_bytes().map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody("receipt-body encoding")
    })? != receipt_record.receipt_intent_bytes
    {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody(
                "receipt intent bytes",
            ),
        );
    }
    let receipt_body_identity = expected_receipt_body.identity().map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody("receipt-body identity")
    })?;
    require_receipt_context_hash(
        stored_receipt_intent_identity,
        receipt_body_identity,
        "stored receipt-intent identity",
    )?;
    let receipt = verify_pseudorandom_zero_sharing_seed_recipient_receipt_320(
        root_terminal,
        roster,
        authenticated_inventory,
        receipt_record.receipt_envelope_bytes,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody("receipt signature")
    })?;
    let receipt_envelope_identity = receipt.receipt_envelope_identity();
    Ok(VerifiedSeedRecipientReceiptCustody320 {
        authenticated_inventory_identity,
        receipt,
        receipt_body_identity,
        receipt_envelope_identity,
    })
}

pub(super) fn verify_completed_seed_recipient_receipt_custody_320(
    bytes: &[u8],
    context: SeedRecipientReceiptCustodyContext320,
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    roster: &Roster,
) -> Result<VerifiedSeedRecipientReceiptCustody320, PseudorandomZeroSharingSeedMasterCustodyError320>
{
    parse_and_verify_receipt_custody_record(bytes, context, root_terminal, roster)
}

fn parse_and_verify_receipt_custody(
    bytes: &[u8],
    context: JoinedCustodyContext320,
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    roster: &Roster,
) -> Result<
    super::pseudorandom_zero_sharing_seed_receipt_320::RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
    PseudorandomZeroSharingSeedMasterCustodyError320,
>{
    let verified = parse_and_verify_receipt_custody_record(
        bytes,
        context.receipt_custody_context(),
        root_terminal,
        roster,
    )?;
    require_receipt_context_hash(
        context.authenticated_recipient_inventory_identity,
        verified.authenticated_inventory_identity,
        "joined authenticated-inventory identity",
    )?;
    require_receipt_context_hash(
        context.receipt_body_identity,
        verified.receipt_body_identity,
        "joined receipt-body identity",
    )?;
    require_receipt_context_hash(
        context.receipt_envelope_identity,
        verified.receipt_envelope_identity,
        "joined receipt-envelope identity",
    )?;
    Ok(verified.receipt)
}

fn verify_retained_delivery_segments(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    recipient_position: u16,
    sender_positions: &[u16],
    segments: &[&[u8]],
) -> Result<
    super::pseudorandom_zero_sharing_seed_delivery_320::RootInventoryMatchedPseudorandomZeroSharingSeedRecipientInventory320,
    PseudorandomZeroSharingSeedMasterCustodyError320,
>{
    if sender_positions.len() != segments.len() {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody(
                "retained delivery count",
            ),
        );
    }
    let mut deliveries = Vec::with_capacity(segments.len());
    for (sender_position, segment) in sender_positions.iter().copied().zip(segments) {
        let descriptor_bytes = derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320(
            root_terminal,
            sender_position,
            recipient_position,
        )
        .and_then(|descriptor| descriptor.canonical_bytes())
        .map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody("delivery descriptor")
        })?;
        let mut verifier = PseudorandomZeroSharingSeedDeliveryVerifier320::new(
            root_terminal,
            sender_position,
            recipient_position,
            &descriptor_bytes,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody("delivery verifier")
        })?;
        let mut segment_cursor = BoundedCursor::new(segment)?;
        while let Some((opening_byte_length, inclusion_proof_byte_length)) =
            verifier.next_entry_byte_lengths()
        {
            let opening_bytes =
                segment_cursor.read_exact(opening_byte_length, "retained delivery opening")?;
            let inclusion_proof_bytes = segment_cursor.read_exact(
                inclusion_proof_byte_length,
                "retained delivery inclusion proof",
            )?;
            verifier
                .absorb_next_entry(opening_bytes, inclusion_proof_bytes)
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody(
                        "retained delivery entry",
                    )
                })?;
        }
        segment_cursor.require_complete("retained delivery trailing bytes")?;
        deliveries.push(verifier.finish().map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody(
                "retained delivery completion",
            )
        })?);
    }
    verify_pseudorandom_zero_sharing_seed_recipient_inventory_320(
        root_terminal,
        recipient_position,
        deliveries,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody(
            "semantic recipient inventory",
        )
    })
}

fn join_and_encode(
    request_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedMasterCustodyError320> {
    let request = parse_join_request(request_bytes)?;
    let verification = parse_verification_context(request.verification_context_bytes)?;
    let (receipt_terminal, roster, preparation_context) =
        verify_public_context(&request, verification)?;
    let local_catalog = parse_and_verify_source_custody(
        request.source_custody_record_bytes,
        request.context,
        preparation_context,
        receipt_terminal.root_terminal(),
    )?;
    let retained_receipt = parse_and_verify_receipt_custody(
        request.receipt_custody_record_bytes,
        request.context,
        receipt_terminal.root_terminal(),
        &roster,
    )?;
    let joined = join_pseudorandom_zero_sharing_seed_masters_320(
        local_catalog,
        retained_receipt,
        receipt_terminal,
    )
    .map_err(|_| PseudorandomZeroSharingSeedMasterCustodyError320::JoinedPayload("master join"))?;
    let payload = joined.custody_payload_bytes().map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::JoinedPayload("payload encoding")
    })?;
    validate_joined_payload(&payload, request.context, preparation_context)?;
    Ok(payload)
}

#[cfg(test)]
pub(super) fn join_and_encode_for_test(
    request_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedMasterCustodyError320> {
    join_and_encode(request_bytes)
}

fn parse_joined_record_and_validate(
    record_bytes: &[u8],
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    let mut cursor = BoundedCursor::new(record_bytes)?;
    cursor.require_magic(JOINED_CUSTODY_RECORD_MAGIC, "joined-record magic")?;
    cursor.require_version("joined-record version")?;
    let context = read_joined_context(&mut cursor)?;
    let verification_context_byte_length = cursor.read_unsigned32("verification-context length")?;
    let root_terminal_certificate_byte_length =
        cursor.read_unsigned32("root-terminal certificate length")?;
    let receipt_terminal_certificate_byte_length =
        cursor.read_unsigned32("receipt-terminal certificate length")?;
    let joined_payload_byte_length = cursor.read_unsigned32("joined payload length")?;
    if verification_context_byte_length == 0
        || root_terminal_certificate_byte_length == 0
        || receipt_terminal_certificate_byte_length == 0
        || joined_payload_byte_length == 0
        || root_terminal_certificate_byte_length > MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH
        || receipt_terminal_certificate_byte_length > MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH
    {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::ResourceLimit(
                "joined-record field length",
            ),
        );
    }
    let verification_context_bytes = cursor.read_exact(
        verification_context_byte_length,
        "joined verification context",
    )?;
    let root_terminal_certificate_bytes = cursor.read_exact(
        root_terminal_certificate_byte_length,
        "joined root-terminal certificate",
    )?;
    let receipt_terminal_certificate_bytes = cursor.read_exact(
        receipt_terminal_certificate_byte_length,
        "joined receipt-terminal certificate",
    )?;
    let joined_payload_bytes = cursor.read_exact(joined_payload_byte_length, "joined payload")?;
    cursor.require_complete("joined-record trailing bytes")?;
    let synthetic_request = JoinRequest320 {
        context,
        source_custody_record_bytes: &[],
        receipt_custody_record_bytes: &[],
        verification_context_bytes,
        root_terminal_certificate_bytes,
        receipt_terminal_certificate_bytes,
    };
    let verification = parse_verification_context(verification_context_bytes)?;
    let (_receipt_terminal, _roster, preparation_context) =
        verify_public_context(&synthetic_request, verification)?;
    validate_joined_payload(joined_payload_bytes, context, preparation_context)
}

fn validate_joined_payload(
    payload_bytes: &[u8],
    context: JoinedCustodyContext320,
    preparation_context: TallyPreparationContext,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    let limits = CanonicalDecodeLimits {
        maximum_tuple_byte_length: 16 * 1024,
        maximum_item_count: 32,
        maximum_item_byte_length: 8 * 1024,
        maximum_nesting_depth: 2,
        maximum_cumulative_work_byte_length: 64 * 1024,
        maximum_cumulative_allocation_byte_length: 64 * 1024,
    };
    let tuple = Zeroizing::new(CanonicalTuple::decode(payload_bytes, &limits).map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::JoinedPayload("canonical encoding")
    })?);
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER
        || tuple.schema_version != CANONICAL_TUPLE_VERSION
        || tuple.items.len() != 17
        || tuple.items[0].item_type() != CanonicalItemType::Ascii
        || tuple.items[0].variable_value_bytes().map_err(|_| {
            PseudorandomZeroSharingSeedMasterCustodyError320::JoinedPayload("object domain")
        })? != PSEUDORANDOM_ZERO_SHARING_JOINED_SEED_MASTER_CUSTODY_DOMAIN.as_bytes()
    {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::JoinedPayload("object header"),
        );
    }
    require_joined_hash(
        &tuple.items[1],
        context.parameter_identity,
        "parameter identity",
    )?;
    require_joined_raw_bytes(
        &tuple.items[2],
        &preparation_context.canonical_bytes(),
        "preparation context",
    )?;
    require_joined_hash(
        &tuple.items[3],
        context.preparation_context_identity,
        "preparation-context identity",
    )?;
    require_joined_unsigned16(
        &tuple.items[4],
        context.preparation_attempt_ordinal,
        "preparation-attempt ordinal",
    )?;
    require_joined_unsigned16(
        &tuple.items[5],
        context.participant_count,
        "participant count",
    )?;
    require_joined_unsigned16(
        &tuple.items[6],
        context.participant_position,
        "participant position",
    )?;
    require_joined_hash(
        &tuple.items[7],
        context.root_terminal_identity,
        "root-terminal identity",
    )?;
    require_joined_hash(
        &tuple.items[8],
        context.root_terminal_certificate_identity,
        "root-terminal certificate identity",
    )?;
    require_joined_hash(
        &tuple.items[9],
        context.receipt_terminal_identity,
        "receipt-terminal identity",
    )?;
    require_joined_hash(
        &tuple.items[10],
        context.receipt_terminal_certificate_identity,
        "receipt-terminal certificate identity",
    )?;
    require_joined_hash(
        &tuple.items[11],
        context.authenticated_recipient_inventory_identity,
        "authenticated recipient-inventory identity",
    )?;
    require_joined_hash(
        &tuple.items[12],
        context.receipt_body_identity,
        "receipt-body identity",
    )?;
    require_joined_hash(
        &tuple.items[13],
        context.receipt_envelope_identity,
        "receipt-envelope identity",
    )?;
    let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        context.parameter_identity,
        preparation_context,
        context.participant_position,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::JoinedPayload("catalog layout")
    })?;
    let subset_master_count = u16::try_from(layout.subset_leaf_count()).map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::ResourceLimit("subset-master count")
    })?;
    let pair_master_count = u16::try_from(layout.pair_leaf_count()).map_err(|_| {
        PseudorandomZeroSharingSeedMasterCustodyError320::ResourceLimit("pair-master count")
    })?;
    require_joined_unsigned16(&tuple.items[14], subset_master_count, "subset-master count")?;
    require_joined_unsigned16(&tuple.items[15], pair_master_count, "pair-master count")?;
    let expected_secret_byte_length = usize::from(subset_master_count)
        .checked_mul(PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH)
        .and_then(|length| {
            usize::from(pair_master_count)
                .checked_mul(PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH)
                .and_then(|pair_length| length.checked_add(pair_length))
        })
        .and_then(|length| length.checked_add(COLLECTIVE_COIN_SOURCE_BYTE_LENGTH))
        .ok_or(
            PseudorandomZeroSharingSeedMasterCustodyError320::ResourceLimit(
                "joined secret byte length",
            ),
        )?;
    if tuple.items[16].item_type() != CanonicalItemType::RawBytes
        || tuple.items[16]
            .variable_value_bytes()
            .map_err(|_| {
                PseudorandomZeroSharingSeedMasterCustodyError320::JoinedPayload(
                    "joined secret bytes",
                )
            })?
            .len()
            != expected_secret_byte_length
    {
        return Err(
            PseudorandomZeroSharingSeedMasterCustodyError320::JoinedPayload(
                "joined secret byte length",
            ),
        );
    }
    Ok(())
}

/// Executes the source-authorized local/global join and returns a stable binary
/// response. A successful payload remains inert encrypted-custody input; it is
/// not a preparation-continuation capability.
pub(crate) fn run_pseudorandom_zero_sharing_seed_master_join_custody_320(
    request_bytes: &[u8],
) -> Zeroizing<Vec<u8>> {
    match join_and_encode(request_bytes) {
        Ok(payload) => encode_join_response(&payload),
        Err(error) => encode_failure_response(error),
    }
}

/// Revalidates one exact authenticated joined-custody plaintext against every
/// retained public terminal carrier. It deliberately constructs no master or
/// preparation-continuation handle.
pub(crate) fn run_pseudorandom_zero_sharing_joined_seed_master_validation_320(
    record_bytes: &[u8],
) -> Zeroizing<Vec<u8>> {
    match parse_joined_record_and_validate(record_bytes) {
        Ok(()) => encode_validation_response(),
        Err(error) => encode_failure_response(error),
    }
}

fn encode_join_response(payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let Ok(payload_byte_length) = u32::try_from(payload.len()) else {
        return encode_failure_response(
            PseudorandomZeroSharingSeedMasterCustodyError320::ResourceLimit(
                "join response payload",
            ),
        );
    };
    let Some(response_byte_length) = RESPONSE_MAGIC
        .len()
        .checked_add(size_of::<u16>() + size_of::<u8>() + size_of::<u32>())
        .and_then(|length| length.checked_add(payload.len()))
    else {
        return encode_failure_response(
            PseudorandomZeroSharingSeedMasterCustodyError320::ResourceLimit("join response"),
        );
    };
    let mut response = Zeroizing::new(Vec::with_capacity(response_byte_length));
    response.extend_from_slice(RESPONSE_MAGIC);
    response.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    response.push(JOIN_RESPONSE_STATUS);
    response.extend_from_slice(&payload_byte_length.to_le_bytes());
    response.extend_from_slice(payload);
    response
}

fn encode_validation_response() -> Zeroizing<Vec<u8>> {
    let mut response = Zeroizing::new(Vec::with_capacity(
        RESPONSE_MAGIC.len() + size_of::<u16>() + 1,
    ));
    response.extend_from_slice(RESPONSE_MAGIC);
    response.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    response.push(VALIDATION_RESPONSE_STATUS);
    response
}

fn encode_failure_response(
    error: PseudorandomZeroSharingSeedMasterCustodyError320,
) -> Zeroizing<Vec<u8>> {
    let mut response = Zeroizing::new(Vec::with_capacity(
        RESPONSE_MAGIC.len() + 2 * size_of::<u16>() + 1,
    ));
    response.extend_from_slice(RESPONSE_MAGIC);
    response.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    response.push(FAILURE_RESPONSE_STATUS);
    response.extend_from_slice(&error.response_code().to_le_bytes());
    response
}

const fn opening_byte_length(coordinate: PseudorandomZeroSharingSeedCatalogCoordinate320) -> usize {
    match coordinate {
        PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(_) => {
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH
        }
        PseudorandomZeroSharingSeedCatalogCoordinate320::Pair { .. } => {
            PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH
        }
        PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin => {
            COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_BYTE_LENGTH
        }
    }
}

fn require_context_match(
    condition: bool,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    if !condition {
        return Err(PseudorandomZeroSharingSeedMasterCustodyError320::ContextMismatch(field));
    }
    Ok(())
}

fn require_source_context_hash(
    actual: Hash512,
    expected: Hash512,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    require_source_coordinate(actual == expected, field)
}

fn require_source_coordinate(
    condition: bool,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    if !condition {
        return Err(PseudorandomZeroSharingSeedMasterCustodyError320::SourceCustody(field));
    }
    Ok(())
}

fn require_source_geometry(
    condition: bool,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    require_source_coordinate(condition, field)
}

fn require_receipt_context_hash(
    actual: Hash512,
    expected: Hash512,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    require_receipt_coordinate(actual == expected, field)
}

fn require_receipt_coordinate(
    condition: bool,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    if !condition {
        return Err(PseudorandomZeroSharingSeedMasterCustodyError320::ReceiptCustody(field));
    }
    Ok(())
}

fn require_receipt_geometry(
    condition: bool,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    require_receipt_coordinate(condition, field)
}

fn require_joined_hash(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    if item.item_type() != CanonicalItemType::Hash512
        || item.canonical_bytes() != expected.as_bytes()
    {
        return Err(PseudorandomZeroSharingSeedMasterCustodyError320::JoinedPayload(field));
    }
    Ok(())
}

fn require_joined_unsigned16(
    item: &CanonicalItem,
    expected: u16,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    if item.item_type() != CanonicalItemType::Unsigned16
        || item.canonical_bytes() != expected.to_le_bytes()
    {
        return Err(PseudorandomZeroSharingSeedMasterCustodyError320::JoinedPayload(field));
    }
    Ok(())
}

fn require_joined_raw_bytes(
    item: &CanonicalItem,
    expected: &[u8],
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedMasterCustodyError320> {
    if item.item_type() != CanonicalItemType::RawBytes
        || item
            .variable_value_bytes()
            .map_err(|_| PseudorandomZeroSharingSeedMasterCustodyError320::JoinedPayload(field))?
            != expected
    {
        return Err(PseudorandomZeroSharingSeedMasterCustodyError320::JoinedPayload(field));
    }
    Ok(())
}
