use core::{cell::RefCell, fmt};

use zeroize::Zeroizing;

use crate::foundation::{CanonicalDecodeLimits, Hash512, Roster};

use super::{
    TallyPreparationContext,
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320::{
        PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320,
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320,
    },
    pseudorandom_zero_sharing_seed_catalog_root_terminal_320::{
        RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
        verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320,
    },
    pseudorandom_zero_sharing_seed_catalog_signature_320::ML_DSA_65_SIGNATURE_BYTE_LENGTH,
    pseudorandom_zero_sharing_seed_delivery_320::derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320,
    pseudorandom_zero_sharing_seed_mailbox_320::{
        ML_KEM_768_CIPHERTEXT_BYTE_LENGTH, PseudorandomZeroSharingSeedMailboxError320,
        PseudorandomZeroSharingSeedMailboxHeaderBody320,
        PseudorandomZeroSharingSeedMailboxVerifier320,
        verify_pseudorandom_zero_sharing_seed_mailbox_authenticated_inconsistency_320,
        verify_pseudorandom_zero_sharing_seed_mailbox_sender_carrier_320,
    },
    pseudorandom_zero_sharing_seed_receipt_320::{
        AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_BYTE_LENGTH,
        PseudorandomZeroSharingSeedRecipientReceiptBody320,
        PseudorandomZeroSharingSignedSeedRecipientReceiptEnvelope320,
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_announcement_320,
    },
};

const REQUEST_MAGIC: &[u8; 4] = b"SLRQ";
const RESPONSE_MAGIC: &[u8; 4] = b"SLRR";
const CODEC_VERSION: u16 = 1;
const OPEN_CONTEXT_OPERATION: u8 = 1;
const COMPLETE_AUTHENTICATION_OPERATION: u8 = 2;
const COMPLETE_RECEIPT_OPERATION: u8 = 3;
const VALIDATE_RECEIPT_OPERATION: u8 = 4;
const CLOSE_CONTEXT_OPERATION: u8 = 5;
const FAILURE_STATUS: u8 = 0;
const OPEN_CONTEXT_STATUS: u8 = 1;
const AUTHENTICATED_INVENTORY_STATUS: u8 = 2;
const COMPLETE_RECEIPT_STATUS: u8 = 3;
const VALIDATION_STATUS: u8 = 4;
const CLOSED_CONTEXT_STATUS: u8 = 5;
const AUTHENTICATED_INCONSISTENCY_STATUS: u8 = 6;
const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const MAXIMUM_COPIED_BUFFER_BYTE_LENGTH: usize = 8 * 1024 * 1024;
const MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH: usize = 1024 * 1024;
const MAXIMUM_PREPARATION_CONTEXT_BYTE_LENGTH: usize = 4096;
const MAXIMUM_PARTICIPANT_COUNT: usize = 32;
const MAXIMUM_ENCRYPTED_CHUNK_COUNT: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedRecipientReceiptKernelError320 {
    MalformedRequest(&'static str),
    ResourceLimit(&'static str),
    ContextMismatch(&'static str),
    PublicVerification(&'static str),
    AuthenticatedInconsistency(&'static str),
    PreparedMismatch(&'static str),
    ContextUnavailable,
    SignatureMismatch,
    PrivateAuthenticationFailed,
}

impl PseudorandomZeroSharingSeedRecipientReceiptKernelError320 {
    const fn response_code(&self) -> u16 {
        match self {
            Self::MalformedRequest(_) => 1,
            Self::ResourceLimit(_) => 2,
            Self::ContextMismatch(_) => 3,
            Self::PublicVerification(_) => 4,
            Self::AuthenticatedInconsistency(_) => 5,
            Self::PreparedMismatch(_) => 6,
            Self::ContextUnavailable => 7,
            Self::SignatureMismatch => 8,
            Self::PrivateAuthenticationFailed => 9,
        }
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedRecipientReceiptKernelError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedRequest(field) => write!(
                formatter,
                "seed-recipient receipt kernel malformed request: {field}"
            ),
            Self::ResourceLimit(field) => write!(
                formatter,
                "seed-recipient receipt kernel resource limit: {field}"
            ),
            Self::ContextMismatch(field) => write!(
                formatter,
                "seed-recipient receipt kernel context mismatch: {field}"
            ),
            Self::PublicVerification(field) => write!(
                formatter,
                "seed-recipient receipt kernel public verification failed: {field}"
            ),
            Self::AuthenticatedInconsistency(field) => write!(
                formatter,
                "seed-recipient receipt kernel authenticated inconsistency: {field}"
            ),
            Self::PreparedMismatch(field) => write!(
                formatter,
                "seed-recipient receipt kernel prepared inventory mismatch: {field}"
            ),
            Self::ContextUnavailable => {
                formatter.write_str("seed-recipient receipt kernel context is unavailable")
            }
            Self::SignatureMismatch => {
                formatter.write_str("seed-recipient receipt kernel signature is invalid")
            }
            Self::PrivateAuthenticationFailed => formatter.write_str(
                "seed-recipient receipt kernel cannot authenticate the signed private carrier",
            ),
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedRecipientReceiptKernelError320 {}

struct OwnedMailboxCarrier320 {
    sender_position: u16,
    header_bytes: Vec<u8>,
    manifest_bytes: Vec<u8>,
    signature_envelope_bytes: Vec<u8>,
    encrypted_chunks: Box<[Vec<u8>]>,
}

struct VerifiedRecipientReceiptContext320 {
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    root_terminal_identity: Hash512,
    participant_count: u16,
    recipient_position: u16,
    root_terminal: RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    roster: Roster,
    pending_carriers: Option<Box<[OwnedMailboxCarrier320]>>,
    authenticated_inventory: Option<AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320>,
    receipt_body: Option<PseudorandomZeroSharingSeedRecipientReceiptBody320>,
}

struct AuthenticatedInconsistencyDisclosure320 {
    sender_position: u16,
    recipient_position: u16,
    authenticated_encryption_key: Zeroizing<[u8; 32]>,
    evidence_identity: Hash512,
}

/// Public predecessor facts recovered by re-verifying the exact canonical
/// receipt-kernel open request. This result carries no private authentication
/// state and authorizes no receipt, burn, or preparation continuation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedPseudorandomZeroSharingSeedRecipientSelection320 {
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    root_terminal_identity: Hash512,
    participant_count: u16,
    recipient_position: u16,
}

impl VerifiedPseudorandomZeroSharingSeedRecipientSelection320 {
    pub(crate) const fn parameter_identity(self) -> Hash512 {
        self.parameter_identity
    }

    pub(crate) const fn preparation_context(self) -> TallyPreparationContext {
        self.preparation_context
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
}

struct VerifiedRecipientReceiptContextRegistry320 {
    next_handle: u32,
    retained: Option<(u32, VerifiedRecipientReceiptContext320)>,
}

impl Default for VerifiedRecipientReceiptContextRegistry320 {
    fn default() -> Self {
        Self {
            next_handle: 1,
            retained: None,
        }
    }
}

thread_local! {
    static VERIFIED_RECIPIENT_RECEIPT_CONTEXTS: RefCell<VerifiedRecipientReceiptContextRegistry320> =
        RefCell::new(VerifiedRecipientReceiptContextRegistry320::default());
}

struct OpenContextRequest320<'a> {
    parameter_identity: Hash512,
    recipient_position: u16,
    preparation_context_bytes: &'a [u8],
    roster_bytes: &'a [u8],
    root_packages: Vec<PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320<'a>>,
    root_terminal_certificate_bytes: &'a [u8],
    carriers: Vec<MailboxCarrierBytes320<'a>>,
}

struct MailboxCarrierBytes320<'a> {
    sender_position: u16,
    header_bytes: &'a [u8],
    manifest_bytes: &'a [u8],
    signature_envelope_bytes: &'a [u8],
    encrypted_chunks: Vec<&'a [u8]>,
}

struct BoundedCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BoundedCursor<'a> {
    fn new(
        bytes: &'a [u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
        if bytes.len() > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
            return Err(
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(
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
    ) -> Result<&'a [u8], PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
        let end = self.offset.checked_add(byte_length).ok_or(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(field),
        )?;
        if end > self.bytes.len() {
            return Err(
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(field),
            );
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_unsigned8(
        &mut self,
        field: &'static str,
    ) -> Result<u8, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
        Ok(self.read_exact(1, field)?[0])
    }

    fn read_unsigned16(
        &mut self,
        field: &'static str,
    ) -> Result<u16, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
        Ok(u16::from_le_bytes(
            self.read_exact(size_of::<u16>(), field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(
                        field,
                    )
                })?,
        ))
    }

    fn read_unsigned32(
        &mut self,
        field: &'static str,
    ) -> Result<usize, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
        let value = u32::from_le_bytes(
            self.read_exact(size_of::<u32>(), field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(
                        field,
                    )
                })?,
        );
        usize::try_from(value).map_err(|_| {
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(field)
        })
    }

    fn read_hash512(
        &mut self,
        field: &'static str,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
        Ok(Hash512::from_bytes(
            self.read_exact(Hash512::BYTE_LENGTH, field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(
                        field,
                    )
                })?,
        ))
    }

    fn read_bounded_bytes(
        &mut self,
        maximum_byte_length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
        let byte_length = self.read_unsigned32(field)?;
        if byte_length == 0 || byte_length > maximum_byte_length {
            return Err(
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(field),
            );
        }
        self.read_exact(byte_length, field)
    }

    fn require_magic(
        &mut self,
        expected: &[u8; 4],
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
        if self.read_exact(expected.len(), field)? != expected {
            return Err(
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(field),
            );
        }
        Ok(())
    }

    fn require_version(
        &mut self,
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
        if self.read_unsigned16(field)? != CODEC_VERSION {
            return Err(
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(field),
            );
        }
        Ok(())
    }

    fn require_complete(
        &self,
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
        if self.offset != self.bytes.len() {
            return Err(
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(field),
            );
        }
        Ok(())
    }
}

fn parse_open_context_request<'a>(
    cursor: &mut BoundedCursor<'a>,
) -> Result<OpenContextRequest320<'a>, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    let parameter_identity = cursor.read_hash512("parameter identity")?;
    let recipient_position = cursor.read_unsigned16("recipient position")?;
    let preparation_context_bytes = cursor.read_bounded_bytes(
        MAXIMUM_PREPARATION_CONTEXT_BYTE_LENGTH,
        "preparation context",
    )?;
    let roster_bytes = cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "roster")?;
    let root_package_count = usize::from(cursor.read_unsigned16("root-package count")?);
    if root_package_count == 0 || root_package_count > MAXIMUM_PARTICIPANT_COUNT {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(
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
                    "root exact-output certificate",
                )?,
                cursor.read_bounded_bytes(
                    MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
                    "root signature envelope",
                )?,
            ),
        );
    }
    let root_terminal_certificate_bytes = cursor.read_bounded_bytes(
        MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
        "root-terminal certificate",
    )?;
    let carrier_count = usize::from(cursor.read_unsigned16("carrier count")?);
    if carrier_count == 0 || carrier_count > MAXIMUM_PARTICIPANT_COUNT - 1 {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(
                "carrier count",
            ),
        );
    }
    let mut carriers = Vec::with_capacity(carrier_count);
    for _ in 0..carrier_count {
        let sender_position = cursor.read_unsigned16("carrier sender position")?;
        let header_bytes =
            cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "mailbox header")?;
        let manifest_bytes =
            cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "mailbox manifest")?;
        let signature_envelope_bytes = cursor.read_bounded_bytes(
            MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
            "mailbox signature envelope",
        )?;
        let chunk_count = usize::from(cursor.read_unsigned16("encrypted chunk count")?);
        if chunk_count == 0 || chunk_count > MAXIMUM_ENCRYPTED_CHUNK_COUNT {
            return Err(
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(
                    "encrypted chunk count",
                ),
            );
        }
        let mut encrypted_chunks = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            encrypted_chunks.push(
                cursor.read_bounded_bytes(MAXIMUM_COPIED_BUFFER_BYTE_LENGTH, "encrypted chunk")?,
            );
        }
        carriers.push(MailboxCarrierBytes320 {
            sender_position,
            header_bytes,
            manifest_bytes,
            signature_envelope_bytes,
            encrypted_chunks,
        });
    }
    cursor.require_complete("open-context trailing bytes")?;
    Ok(OpenContextRequest320 {
        parameter_identity,
        recipient_position,
        preparation_context_bytes,
        roster_bytes,
        root_packages,
        root_terminal_certificate_bytes,
        carriers,
    })
}

fn verify_open_context(
    request: OpenContextRequest320<'_>,
) -> Result<
    VerifiedRecipientReceiptContext320,
    PseudorandomZeroSharingSeedRecipientReceiptKernelError320,
> {
    let preparation_context = TallyPreparationContext::from_canonical_bytes(
        request.preparation_context_bytes,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
            "preparation context",
        )
    })?;
    let roster =
        Roster::decode(request.roster_bytes, &CanonicalDecodeLimits::default()).map_err(|_| {
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification("roster")
        })?;
    if roster.encode().map_err(|_| {
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification("roster")
    })? != request.roster_bytes
    {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
                "noncanonical roster",
            ),
        );
    }
    let participant_count = preparation_context.participant_count();
    if roster.entries.len() != usize::from(participant_count)
        || request.root_packages.len() != roster.entries.len()
        || request.carriers.len() != roster.entries.len().saturating_sub(1)
        || request.recipient_position >= participant_count
        || roster.entries[usize::from(request.recipient_position)].roster_position
            != request.recipient_position
        || roster.roster_hash().map_err(|_| {
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
                "roster identity",
            )
        })? != preparation_context.roster_hash()
    {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
                "roster scope",
            ),
        );
    }
    let preparation_context_identity = preparation_context.identity();
    let root_inventory = verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
        request.parameter_identity,
        preparation_context,
        &roster,
        &request.root_packages,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
            "root inventory",
        )
    })?;
    let root_terminal = verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
        root_inventory,
        &roster,
        request.root_terminal_certificate_bytes,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
            "root terminal",
        )
    })?;
    let root_terminal_identity = root_terminal.identity().map_err(|_| {
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
            "root-terminal identity",
        )
    })?;
    let expected_sender_positions = (0..participant_count)
        .filter(|sender_position| *sender_position != request.recipient_position);
    let mut owned_carriers = Vec::with_capacity(request.carriers.len());
    for (carrier, expected_sender_position) in
        request.carriers.into_iter().zip(expected_sender_positions)
    {
        if carrier.sender_position != expected_sender_position {
            return Err(
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
                    "carrier order",
                ),
            );
        }
        let descriptor_bytes = derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320(
            &root_terminal,
            expected_sender_position,
            request.recipient_position,
        )
        .and_then(|descriptor| descriptor.canonical_bytes())
        .map_err(|_| {
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
                "delivery descriptor",
            )
        })?;
        verify_pseudorandom_zero_sharing_seed_mailbox_sender_carrier_320(
            &root_terminal,
            &roster,
            expected_sender_position,
            request.recipient_position,
            &descriptor_bytes,
            carrier.header_bytes,
            carrier.manifest_bytes,
            carrier.signature_envelope_bytes,
            &carrier.encrypted_chunks,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
                "authenticated mailbox carrier",
            )
        })?;
        let header = PseudorandomZeroSharingSeedMailboxHeaderBody320::from_canonical_bytes(
            carrier.header_bytes,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
                "mailbox header",
            )
        })?;
        if header.encapsulation_ciphertext().len() != ML_KEM_768_CIPHERTEXT_BYTE_LENGTH {
            return Err(
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
                    "encapsulation ciphertext",
                ),
            );
        }
        owned_carriers.push(OwnedMailboxCarrier320 {
            sender_position: expected_sender_position,
            header_bytes: carrier.header_bytes.to_vec(),
            manifest_bytes: carrier.manifest_bytes.to_vec(),
            signature_envelope_bytes: carrier.signature_envelope_bytes.to_vec(),
            encrypted_chunks: carrier
                .encrypted_chunks
                .into_iter()
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        });
    }
    Ok(VerifiedRecipientReceiptContext320 {
        parameter_identity: request.parameter_identity,
        preparation_context_identity,
        root_terminal_identity,
        participant_count,
        recipient_position: request.recipient_position,
        root_terminal,
        roster,
        pending_carriers: Some(owned_carriers.into_boxed_slice()),
        authenticated_inventory: None,
        receipt_body: None,
    })
}

fn verify_canonical_open_request(
    request_bytes: &[u8],
) -> Result<
    VerifiedRecipientReceiptContext320,
    PseudorandomZeroSharingSeedRecipientReceiptKernelError320,
> {
    let mut cursor = BoundedCursor::new(request_bytes)?;
    cursor.require_magic(REQUEST_MAGIC, "open-request magic")?;
    cursor.require_version("open-request version")?;
    if cursor.read_unsigned8("open-request operation")? != OPEN_CONTEXT_OPERATION {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(
                "open-request operation",
            ),
        );
    }
    verify_open_context(parse_open_context_request(&mut cursor)?)
}

/// Re-verifies every public byte selected before private recipient
/// authentication and returns only its exact public scope.
pub(crate) fn verify_pseudorandom_zero_sharing_seed_recipient_selection_320(
    canonical_open_request_bytes: &[u8],
) -> Result<
    VerifiedPseudorandomZeroSharingSeedRecipientSelection320,
    PseudorandomZeroSharingSeedRecipientReceiptKernelError320,
> {
    let context = verify_canonical_open_request(canonical_open_request_bytes)?;
    Ok(VerifiedPseudorandomZeroSharingSeedRecipientSelection320 {
        parameter_identity: context.parameter_identity,
        preparation_context: context
            .root_terminal
            .root_inventory()
            .root_body(0)
            .ok_or(
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
                    "preparation context",
                ),
            )?
            .layout()
            .preparation_context(),
        root_terminal_identity: context.root_terminal_identity,
        participant_count: context.participant_count,
        recipient_position: context.recipient_position,
    })
}

/// Re-verifies a retained disclosure against the exact signed encrypted
/// carrier inventory that preceded private authentication. The disclosed key
/// is consumed by this call and never retained in the returned typed result.
pub(crate) fn verify_pseudorandom_zero_sharing_seed_recipient_authenticated_inconsistency_disclosure_320(
    canonical_open_request_bytes: &[u8],
    expected_sender_position: u16,
    expected_recipient_position: u16,
    disclosed_authenticated_encryption_key: [u8; 32],
) -> Result<
    super::VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320,
    PseudorandomZeroSharingSeedRecipientReceiptKernelError320,
> {
    let context = verify_canonical_open_request(canonical_open_request_bytes)?;
    if context.recipient_position != expected_recipient_position {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextMismatch(
                "disclosure recipient position",
            ),
        );
    }
    let carrier = context
        .pending_carriers
        .as_ref()
        .and_then(|carriers| {
            carriers
                .iter()
                .find(|carrier| carrier.sender_position == expected_sender_position)
        })
        .ok_or(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextMismatch(
                "disclosure sender position",
            ),
        )?;
    let descriptor_bytes = derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320(
        &context.root_terminal,
        expected_sender_position,
        expected_recipient_position,
    )
    .and_then(|descriptor| descriptor.canonical_bytes())
    .map_err(|_| {
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
            "disclosure descriptor",
        )
    })?;
    let encrypted_chunk_references = carrier
        .encrypted_chunks
        .iter()
        .map(|chunk| chunk.as_slice())
        .collect::<Vec<_>>();
    let disclosed_authenticated_encryption_key =
        Zeroizing::new(disclosed_authenticated_encryption_key);
    let evidence = verify_pseudorandom_zero_sharing_seed_mailbox_authenticated_inconsistency_320(
        &context.root_terminal,
        &context.roster,
        expected_sender_position,
        expected_recipient_position,
        &descriptor_bytes,
        &carrier.header_bytes,
        &carrier.manifest_bytes,
        &carrier.signature_envelope_bytes,
        &encrypted_chunk_references,
        &disclosed_authenticated_encryption_key,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
            "authenticated inconsistency disclosure",
        )
    })?;
    Ok(evidence)
}

/// Re-verifies one retained disclosure and additionally binds it to the exact
/// evidence identity retained by authenticated local custody.
pub(crate) fn verify_pseudorandom_zero_sharing_seed_recipient_authenticated_inconsistency_320(
    canonical_open_request_bytes: &[u8],
    expected_sender_position: u16,
    expected_recipient_position: u16,
    disclosed_authenticated_encryption_key: [u8; 32],
    expected_evidence_identity: Hash512,
) -> Result<
    super::VerifiedPseudorandomZeroSharingSeedMailboxAuthenticatedInconsistency320,
    PseudorandomZeroSharingSeedRecipientReceiptKernelError320,
> {
    let evidence =
        verify_pseudorandom_zero_sharing_seed_recipient_authenticated_inconsistency_disclosure_320(
            canonical_open_request_bytes,
            expected_sender_position,
            expected_recipient_position,
            disclosed_authenticated_encryption_key,
        )?;
    if evidence.identity() != expected_evidence_identity {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextMismatch(
                "authenticated inconsistency identity",
            ),
        );
    }
    Ok(evidence)
}

fn retain_verified_context(
    context: VerifiedRecipientReceiptContext320,
) -> Result<u32, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    VERIFIED_RECIPIENT_RECEIPT_CONTEXTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        if registry.retained.is_some() {
            return Err(
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(
                    "retained context count",
                ),
            );
        }
        let handle = registry.next_handle;
        if handle == 0 {
            return Err(
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(
                    "context handle",
                ),
            );
        }
        registry.next_handle = handle.checked_add(1).ok_or(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(
                "context handle",
            ),
        )?;
        registry.retained = Some((handle, context));
        Ok(handle)
    })
}

fn with_verified_context<ResultValue>(
    handle: u32,
    operation: impl FnOnce(
        &VerifiedRecipientReceiptContext320,
    ) -> Result<
        ResultValue,
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320,
    >,
) -> Result<ResultValue, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    VERIFIED_RECIPIENT_RECEIPT_CONTEXTS.with(|registry| {
        let registry = registry.borrow();
        let context = registry
            .retained
            .as_ref()
            .filter(|(retained_handle, _context)| *retained_handle == handle)
            .map(|(_retained_handle, context)| context)
            .ok_or(PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextUnavailable)?;
        operation(context)
    })
}

fn with_verified_context_mut<ResultValue>(
    handle: u32,
    operation: impl FnOnce(
        &mut VerifiedRecipientReceiptContext320,
    ) -> Result<
        ResultValue,
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320,
    >,
) -> Result<ResultValue, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    VERIFIED_RECIPIENT_RECEIPT_CONTEXTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        let context = registry
            .retained
            .as_mut()
            .filter(|(retained_handle, _context)| *retained_handle == handle)
            .map(|(_retained_handle, context)| context)
            .ok_or(PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextUnavailable)?;
        operation(context)
    })
}

fn close_verified_context(
    handle: u32,
) -> Result<(), PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    VERIFIED_RECIPIENT_RECEIPT_CONTEXTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        if !matches!(registry.retained, Some((retained_handle, _)) if retained_handle == handle) {
            return Err(
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextUnavailable,
            );
        }
        registry.retained = None;
        Ok(())
    })
}

fn authenticate_inventory(
    context: &mut VerifiedRecipientReceiptContext320,
    shared_secrets: Vec<[u8; 32]>,
) -> Result<
    Option<AuthenticatedInconsistencyDisclosure320>,
    PseudorandomZeroSharingSeedRecipientReceiptKernelError320,
> {
    if context.authenticated_inventory.is_some() || context.receipt_body.is_some() {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextMismatch(
                "inventory is already authenticated",
            ),
        );
    }
    let carrier_count = context
        .pending_carriers
        .as_ref()
        .ok_or(PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextUnavailable)?
        .len();
    if carrier_count != shared_secrets.len() {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(
                "shared-secret count",
            ),
        );
    }
    let carriers = context
        .pending_carriers
        .take()
        .ok_or(PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextUnavailable)?;
    let mut authenticated_deliveries = Vec::with_capacity(carriers.len());
    for (carrier, shared_secret) in carriers.into_vec().into_iter().zip(shared_secrets) {
        let shared_secret = Zeroizing::new(shared_secret);
        let mut verifier = PseudorandomZeroSharingSeedMailboxVerifier320::new_with_shared_secret(
            &context.root_terminal,
            &context.roster,
            carrier.sender_position,
            context.recipient_position,
            &carrier.header_bytes,
            &carrier.manifest_bytes,
            &carrier.signature_envelope_bytes,
            &shared_secret,
        )
        .map_err(|error| {
            if matches!(
                error,
                PseudorandomZeroSharingSeedMailboxError320::AuthenticatedEncryptionKeyCommitmentMismatch
            ) {
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PrivateAuthenticationFailed
            } else {
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
                    "mailbox control",
                )
            }
        })?;
        let authenticated_encryption_key =
            Zeroizing::new(verifier.authenticated_encryption_key_for_inconsistency());
        let mut authenticated_delivery_failure = false;
        for encrypted_chunk in &carrier.encrypted_chunks {
            if verifier
                .absorb_next_encrypted_chunk(encrypted_chunk)
                .is_err()
            {
                authenticated_delivery_failure = true;
                break;
            }
        }
        let authenticated_delivery = if authenticated_delivery_failure {
            None
        } else {
            verifier.finish().ok()
        };
        if let Some(authenticated_delivery) = authenticated_delivery {
            authenticated_deliveries.push(authenticated_delivery);
            continue;
        }
        let descriptor_bytes = derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320(
            &context.root_terminal,
            carrier.sender_position,
            context.recipient_position,
        )
        .and_then(|descriptor| descriptor.canonical_bytes())
        .map_err(|_| {
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
                "mailbox disclosure descriptor",
            )
        })?;
        let encrypted_chunk_references = carrier
            .encrypted_chunks
            .iter()
            .map(|chunk| chunk.as_slice())
            .collect::<Vec<_>>();
        match verify_pseudorandom_zero_sharing_seed_mailbox_authenticated_inconsistency_320(
            &context.root_terminal,
            &context.roster,
            carrier.sender_position,
            context.recipient_position,
            &descriptor_bytes,
            &carrier.header_bytes,
            &carrier.manifest_bytes,
            &carrier.signature_envelope_bytes,
            &encrypted_chunk_references,
            &authenticated_encryption_key,
        ) {
            Ok(evidence) => {
                return Ok(Some(AuthenticatedInconsistencyDisclosure320 {
                    sender_position: carrier.sender_position,
                    recipient_position: context.recipient_position,
                    authenticated_encryption_key,
                    evidence_identity: evidence.identity(),
                }));
            }
            Err(
                PseudorandomZeroSharingSeedMailboxError320::AuthenticatedDecryptionFailed
                | PseudorandomZeroSharingSeedMailboxError320::AuthenticatedEncryptionKeyCommitmentMismatch,
            ) => {
                return Err(
                    PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PrivateAuthenticationFailed,
                );
            }
            Err(_) => {
                return Err(
                    PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
                        "mailbox disclosure verification",
                    ),
                );
            }
        }
    }
    let inventory = verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
        &context.root_terminal,
        context.recipient_position,
        authenticated_deliveries,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
            "complete recipient inventory",
        )
    })?;
    let receipt_body = PseudorandomZeroSharingSeedRecipientReceiptBody320::new(&inventory)
        .map_err(|_| {
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
                "receipt intent",
            )
        })?;
    context.authenticated_inventory = Some(inventory);
    context.receipt_body = Some(receipt_body);
    Ok(None)
}

fn require_matching_bytes(
    actual: &[u8],
    expected: &[u8],
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    if actual != expected {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PreparedMismatch(field),
        );
    }
    Ok(())
}

fn require_matching_hash(
    actual: Hash512,
    expected: Hash512,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    if actual != expected {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PreparedMismatch(field),
        );
    }
    Ok(())
}

fn require_authenticated_context(
    context: &VerifiedRecipientReceiptContext320,
) -> Result<
    (
        &AuthenticatedPseudorandomZeroSharingSeedRecipientInventory320,
        PseudorandomZeroSharingSeedRecipientReceiptBody320,
    ),
    PseudorandomZeroSharingSeedRecipientReceiptKernelError320,
> {
    Ok((
        context
            .authenticated_inventory
            .as_ref()
            .ok_or(PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextUnavailable)?,
        context
            .receipt_body
            .ok_or(PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextUnavailable)?,
    ))
}

fn verify_validation_context(
    cursor: &mut BoundedCursor<'_>,
    context: &VerifiedRecipientReceiptContext320,
) -> Result<(), PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    if cursor.read_hash512("validation parameter identity")? != context.parameter_identity
        || cursor.read_unsigned16("validation participant count")? != context.participant_count
        || cursor.read_unsigned16("validation preparation attempt")? != PREPARATION_ATTEMPT_ORDINAL
        || cursor.read_hash512("validation preparation-context identity")?
            != context.preparation_context_identity
        || cursor.read_unsigned16("validation recipient position")? != context.recipient_position
        || cursor.read_hash512("validation root-terminal identity")?
            != context.root_terminal_identity
    {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextMismatch(
                "validation context",
            ),
        );
    }
    Ok(())
}

fn verify_prepared_inventory(
    cursor: &mut BoundedCursor<'_>,
    context: &VerifiedRecipientReceiptContext320,
) -> Result<(), PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    let (inventory, receipt_body) = require_authenticated_context(context)?;
    let inventory_body_bytes = inventory.body().canonical_bytes().map_err(|_| {
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
            "authenticated-inventory body",
        )
    })?;
    require_matching_bytes(
        cursor.read_bounded_bytes(
            MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
            "authenticated-inventory body",
        )?,
        &inventory_body_bytes,
        "authenticated-inventory body",
    )?;
    require_matching_hash(
        cursor.read_hash512("authenticated-inventory identity")?,
        inventory.body().identity().map_err(|_| {
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
                "authenticated-inventory identity",
            )
        })?,
        "authenticated-inventory identity",
    )?;
    let segment_count = usize::from(cursor.read_unsigned16("local segment count")?);
    if segment_count != inventory.local_seed_custody_segments().len() {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PreparedMismatch(
                "local segment count",
            ),
        );
    }
    for expected_segment in inventory.local_seed_custody_segments() {
        require_matching_bytes(
            cursor.read_bounded_bytes(MAXIMUM_COPIED_BUFFER_BYTE_LENGTH, "local seed segment")?,
            expected_segment,
            "local seed segment",
        )?;
    }
    let receipt_body_bytes = receipt_body.canonical_bytes().map_err(|_| {
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
            "receipt intent",
        )
    })?;
    require_matching_bytes(
        cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "receipt intent")?,
        &receipt_body_bytes,
        "receipt intent",
    )?;
    require_matching_hash(
        cursor.read_hash512("receipt-intent identity")?,
        receipt_body.identity().map_err(|_| {
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
                "receipt-intent identity",
            )
        })?,
        "receipt-intent identity",
    )
}

fn response_header(status: u8) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(7));
    bytes.extend_from_slice(RESPONSE_MAGIC);
    bytes.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    bytes.push(status);
    bytes
}

fn append_unsigned16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn append_unsigned32(
    output: &mut Vec<u8>,
    value: usize,
) -> Result<(), PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    output.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| {
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(
                    "encoded byte length",
                )
            })?
            .to_le_bytes(),
    );
    Ok(())
}

fn append_bounded_bytes(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    append_unsigned32(output, value.len())?;
    output.extend_from_slice(value);
    if output.len() > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(
                "response byte length",
            ),
        );
    }
    Ok(())
}

fn encode_failure_response(
    error: &PseudorandomZeroSharingSeedRecipientReceiptKernelError320,
) -> Zeroizing<Vec<u8>> {
    let mut bytes = response_header(FAILURE_STATUS);
    append_unsigned16(&mut bytes, error.response_code());
    bytes
}

fn encode_open_response(
    handle: u32,
    context: &VerifiedRecipientReceiptContext320,
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    let recipient_entry = &context.roster.entries[usize::from(context.recipient_position)];
    let carriers = context
        .pending_carriers
        .as_ref()
        .ok_or(PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextUnavailable)?;
    let mut bytes = response_header(OPEN_CONTEXT_STATUS);
    bytes.extend_from_slice(&handle.to_le_bytes());
    bytes.extend_from_slice(context.parameter_identity.as_bytes());
    bytes.extend_from_slice(context.preparation_context_identity.as_bytes());
    bytes.extend_from_slice(context.root_terminal_identity.as_bytes());
    append_unsigned16(&mut bytes, PREPARATION_ATTEMPT_ORDINAL);
    append_unsigned16(&mut bytes, context.participant_count);
    append_unsigned16(&mut bytes, context.recipient_position);
    bytes.extend_from_slice(&recipient_entry.signing_verification_key);
    bytes.extend_from_slice(&recipient_entry.mailbox_encapsulation_key);
    append_unsigned16(
        &mut bytes,
        u16::try_from(carriers.len()).map_err(|_| {
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(
                "carrier count",
            )
        })?,
    );
    for carrier in carriers {
        let header = PseudorandomZeroSharingSeedMailboxHeaderBody320::from_canonical_bytes(
            &carrier.header_bytes,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::PublicVerification(
                "mailbox header",
            )
        })?;
        bytes.extend_from_slice(header.encapsulation_ciphertext());
    }
    Ok(bytes)
}

fn append_prepared_inventory(
    bytes: &mut Vec<u8>,
    context: &VerifiedRecipientReceiptContext320,
) -> Result<(), PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    let (inventory, receipt_body) = require_authenticated_context(context)?;
    let inventory_body_bytes = inventory.body().canonical_bytes().map_err(|_| {
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
            "authenticated-inventory body",
        )
    })?;
    append_bounded_bytes(bytes, &inventory_body_bytes)?;
    bytes.extend_from_slice(
        inventory
            .body()
            .identity()
            .map_err(|_| {
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
                    "authenticated-inventory identity",
                )
            })?
            .as_bytes(),
    );
    append_unsigned16(
        bytes,
        u16::try_from(inventory.local_seed_custody_segments().len()).map_err(|_| {
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(
                "local segment count",
            )
        })?,
    );
    for segment in inventory.local_seed_custody_segments() {
        append_bounded_bytes(bytes, segment)?;
    }
    let receipt_body_bytes = receipt_body.canonical_bytes().map_err(|_| {
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
            "receipt intent",
        )
    })?;
    if receipt_body_bytes.len() != PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_BODY_BYTE_LENGTH
    {
        return Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
                "receipt-intent byte length",
            ),
        );
    }
    append_bounded_bytes(bytes, &receipt_body_bytes)?;
    bytes.extend_from_slice(
        receipt_body
            .identity()
            .map_err(|_| {
                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::AuthenticatedInconsistency(
                    "receipt-intent identity",
                )
            })?
            .as_bytes(),
    );
    Ok(())
}

fn encode_authenticated_inventory_response(
    context: &VerifiedRecipientReceiptContext320,
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    let mut bytes = response_header(AUTHENTICATED_INVENTORY_STATUS);
    append_prepared_inventory(&mut bytes, context)?;
    Ok(bytes)
}

fn encode_authenticated_inconsistency_response(
    disclosure: AuthenticatedInconsistencyDisclosure320,
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    let mut bytes = response_header(AUTHENTICATED_INCONSISTENCY_STATUS);
    append_unsigned16(&mut bytes, disclosure.sender_position);
    append_unsigned16(&mut bytes, disclosure.recipient_position);
    bytes.extend_from_slice(disclosure.authenticated_encryption_key.as_ref());
    bytes.extend_from_slice(disclosure.evidence_identity.as_bytes());
    Ok(bytes)
}

fn encode_complete_receipt_response(
    receipt_envelope_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    if receipt_envelope_bytes.len()
        != PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_ENVELOPE_BYTE_LENGTH
    {
        return Err(PseudorandomZeroSharingSeedRecipientReceiptKernelError320::SignatureMismatch);
    }
    let mut bytes = response_header(COMPLETE_RECEIPT_STATUS);
    append_bounded_bytes(&mut bytes, receipt_envelope_bytes)?;
    Ok(bytes)
}

fn parse_handle(
    cursor: &mut BoundedCursor<'_>,
) -> Result<u32, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    u32::try_from(cursor.read_unsigned32("context handle")?).map_err(|_| {
        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(
            "context handle",
        )
    })
}

fn parse_request(
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedRecipientReceiptKernelError320> {
    let mut cursor = BoundedCursor::new(bytes)?;
    cursor.require_magic(REQUEST_MAGIC, "request magic")?;
    cursor.require_version("request version")?;
    let operation = cursor.read_unsigned8("operation")?;
    match operation {
        OPEN_CONTEXT_OPERATION => {
            let verified = verify_open_context(parse_open_context_request(&mut cursor)?)?;
            let handle = retain_verified_context(verified)?;
            with_verified_context(handle, |context| encode_open_response(handle, context))
        }
        COMPLETE_AUTHENTICATION_OPERATION => {
            let handle = parse_handle(&mut cursor)?;
            let shared_secret_count = usize::from(cursor.read_unsigned16("shared-secret count")?);
            if shared_secret_count == 0 || shared_secret_count > MAXIMUM_PARTICIPANT_COUNT - 1 {
                return Err(
                    PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ResourceLimit(
                        "shared-secret count",
                    ),
                );
            }
            let shared_secrets = (0..shared_secret_count)
                .map(|_| {
                    cursor
                        .read_exact(32, "shared secret")?
                        .try_into()
                        .map_err(|_| {
                            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(
                                "shared secret",
                            )
                        })
                })
                .collect::<Result<Vec<[u8; 32]>, _>>()?;
            cursor.require_complete("complete-authentication trailing bytes")?;
            with_verified_context_mut(handle, |context| {
                match authenticate_inventory(context, shared_secrets)? {
                    Some(disclosure) => encode_authenticated_inconsistency_response(disclosure),
                    None => encode_authenticated_inventory_response(context),
                }
            })
        }
        COMPLETE_RECEIPT_OPERATION => {
            let handle = parse_handle(&mut cursor)?;
            with_verified_context(handle, |context| {
                verify_prepared_inventory(&mut cursor, context)?;
                let signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH] = cursor
                    .read_exact(ML_DSA_65_SIGNATURE_BYTE_LENGTH, "receipt signature")?
                    .try_into()
                    .map_err(|_| {
                        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(
                            "receipt signature",
                        )
                    })?;
                cursor.require_complete("complete-receipt trailing bytes")?;
                let receipt_body = context.receipt_body.ok_or(
                    PseudorandomZeroSharingSeedRecipientReceiptKernelError320::ContextUnavailable,
                )?;
                let receipt_envelope_bytes =
                    PseudorandomZeroSharingSignedSeedRecipientReceiptEnvelope320::new(
                        receipt_body,
                        signature,
                    )
                    .canonical_bytes()
                    .map_err(|_| {
                        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::SignatureMismatch
                    })?;
                let verified =
                    verify_pseudorandom_zero_sharing_seed_recipient_receipt_announcement_320(
                        &context.root_terminal,
                        &context.roster,
                        context.recipient_position,
                        &receipt_envelope_bytes,
                    )
                    .map_err(|_| {
                        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::SignatureMismatch
                    })?;
                if verified.receipt_body() != receipt_body {
                    return Err(
                        PseudorandomZeroSharingSeedRecipientReceiptKernelError320::SignatureMismatch,
                    );
                }
                encode_complete_receipt_response(&receipt_envelope_bytes)
            })
        }
        VALIDATE_RECEIPT_OPERATION => {
            let handle = parse_handle(&mut cursor)?;
            with_verified_context(handle, |context| {
                verify_validation_context(&mut cursor, context)?;
                verify_prepared_inventory(&mut cursor, context)?;
                match cursor.read_unsigned8("receipt-envelope presence")? {
                    0 => {}
                    1 => {
                        let receipt_envelope_bytes = cursor.read_bounded_bytes(
                            MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
                            "receipt envelope",
                        )?;
                        let verified = verify_pseudorandom_zero_sharing_seed_recipient_receipt_announcement_320(
                            &context.root_terminal,
                            &context.roster,
                            context.recipient_position,
                            receipt_envelope_bytes,
                        )
                        .map_err(|_| {
                            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::SignatureMismatch
                        })?;
                        if Some(verified.receipt_body()) != context.receipt_body {
                            return Err(
                                PseudorandomZeroSharingSeedRecipientReceiptKernelError320::SignatureMismatch,
                            );
                        }
                    }
                    _ => {
                        return Err(
                            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(
                                "receipt-envelope presence",
                            ),
                        );
                    }
                }
                cursor.require_complete("validate-receipt trailing bytes")?;
                Ok(response_header(VALIDATION_STATUS))
            })
        }
        CLOSE_CONTEXT_OPERATION => {
            let handle = parse_handle(&mut cursor)?;
            cursor.require_complete("close-context trailing bytes")?;
            close_verified_context(handle)?;
            Ok(response_header(CLOSED_CONTEXT_STATUS))
        }
        _ => Err(
            PseudorandomZeroSharingSeedRecipientReceiptKernelError320::MalformedRequest(
                "operation",
            ),
        ),
    }
}

pub(crate) fn run_pseudorandom_zero_sharing_seed_recipient_receipt_kernel_320(
    input: &[u8],
) -> Zeroizing<Vec<u8>> {
    match parse_request(input) {
        Ok(response) => response,
        Err(error) => encode_failure_response(&error),
    }
}

#[cfg(test)]
pub(crate) fn clear_pseudorandom_zero_sharing_seed_recipient_receipt_contexts_for_test_320() {
    VERIFIED_RECIPIENT_RECEIPT_CONTEXTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.retained = None;
        registry.next_handle = 1;
    });
}
