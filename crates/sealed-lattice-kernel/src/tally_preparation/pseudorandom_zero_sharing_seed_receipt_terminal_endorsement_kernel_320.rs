use core::{cell::RefCell, fmt};

use zeroize::Zeroizing;

use crate::foundation::{
    CanonicalDecodeLimits, Hash512, ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, Roster,
};

use super::{
    TallyPreparationContext,
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320::{
        PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320,
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320,
    },
    pseudorandom_zero_sharing_seed_catalog_root_terminal_320::verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320,
    pseudorandom_zero_sharing_seed_catalog_signature_320::ML_DSA_65_SIGNATURE_BYTE_LENGTH,
    pseudorandom_zero_sharing_seed_master_custody_320::{
        SeedRecipientReceiptCustodyContext320, verify_completed_seed_recipient_receipt_custody_320,
    },
    pseudorandom_zero_sharing_seed_receipt_terminal_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH,
        PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320,
        complete_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_signature_320,
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320,
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_signature_320,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_inventory_320,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320,
    },
};

const REQUEST_MAGIC: &[u8; 4] = b"SLTQ";
const RESPONSE_MAGIC: &[u8; 4] = b"SLTP";
const CODEC_VERSION: u16 = 1;
const OPEN_CONTEXT_OPERATION: u8 = 1;
const PREPARE_ENDORSEMENT_OPERATION: u8 = 2;
const COMPLETE_ENDORSEMENT_OPERATION: u8 = 3;
const VALIDATE_ENDORSEMENT_OPERATION: u8 = 4;
const CLOSE_CONTEXT_OPERATION: u8 = 5;
const FAILURE_STATUS: u8 = 0;
const OPEN_CONTEXT_STATUS: u8 = 1;
const PREPARED_ENDORSEMENT_STATUS: u8 = 2;
const COMPLETE_ENDORSEMENT_STATUS: u8 = 3;
const VALIDATION_STATUS: u8 = 4;
const CLOSED_CONTEXT_STATUS: u8 = 5;
const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const MAXIMUM_COPIED_BUFFER_BYTE_LENGTH: usize = 8 * 1024 * 1024;
const MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH: usize = 1024 * 1024;
const MAXIMUM_PREPARATION_CONTEXT_BYTE_LENGTH: usize = 4096;
const MAXIMUM_PARTICIPANT_COUNT: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320 {
    MalformedRequest(&'static str),
    ResourceLimit(&'static str),
    ContextMismatch(&'static str),
    PublicVerification(&'static str),
    ReceiptCustody(&'static str),
    PreparedMismatch(&'static str),
    ContextUnavailable,
    SignatureMismatch,
}

impl PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320 {
    const fn response_code(&self) -> u16 {
        match self {
            Self::MalformedRequest(_) => 1,
            Self::ResourceLimit(_) => 2,
            Self::ContextMismatch(_) => 3,
            Self::PublicVerification(_) => 4,
            Self::ReceiptCustody(_) => 5,
            Self::PreparedMismatch(_) => 6,
            Self::ContextUnavailable => 7,
            Self::SignatureMismatch => 8,
        }
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedRequest(field) => write!(
                formatter,
                "seed-receipt terminal endorsement kernel malformed request: {field}"
            ),
            Self::ResourceLimit(field) => write!(
                formatter,
                "seed-receipt terminal endorsement kernel resource limit: {field}"
            ),
            Self::ContextMismatch(field) => write!(
                formatter,
                "seed-receipt terminal endorsement kernel context mismatch: {field}"
            ),
            Self::PublicVerification(field) => write!(
                formatter,
                "seed-receipt terminal endorsement kernel public verification failed: {field}"
            ),
            Self::ReceiptCustody(field) => write!(
                formatter,
                "seed-receipt terminal endorsement kernel receipt custody failed: {field}"
            ),
            Self::PreparedMismatch(field) => write!(
                formatter,
                "seed-receipt terminal endorsement kernel prepared inventory mismatch: {field}"
            ),
            Self::ContextUnavailable => formatter
                .write_str("seed-receipt terminal endorsement kernel context is unavailable"),
            Self::SignatureMismatch => {
                formatter.write_str("seed-receipt terminal endorsement kernel signature is invalid")
            }
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320 {}

struct VerifiedTerminalEndorsementContext320 {
    custody_context: SeedRecipientReceiptCustodyContext320,
    prepared_endorsement: PreparedPseudorandomZeroSharingSeedRecipientReceiptTerminalEndorsement320,
    roster: Roster,
    ordered_receipt_envelope_bytes: Box<[Vec<u8>]>,
    retained_local_receipt_body_identity: Hash512,
    retained_local_receipt_envelope_identity: Hash512,
}

struct VerifiedTerminalEndorsementContextRegistry320 {
    next_handle: u32,
    retained: Option<(u32, VerifiedTerminalEndorsementContext320)>,
}

impl Default for VerifiedTerminalEndorsementContextRegistry320 {
    fn default() -> Self {
        Self {
            next_handle: 1,
            retained: None,
        }
    }
}

thread_local! {
    static VERIFIED_TERMINAL_ENDORSEMENT_CONTEXTS: RefCell<VerifiedTerminalEndorsementContextRegistry320> =
        RefCell::new(VerifiedTerminalEndorsementContextRegistry320::default());
}

struct OpenContextRequest320<'a> {
    parameter_identity: Hash512,
    endorser_position: u16,
    preparation_context_bytes: &'a [u8],
    roster_bytes: &'a [u8],
    root_packages: Vec<PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320<'a>>,
    root_terminal_certificate_bytes: &'a [u8],
    receipt_envelope_bytes: Vec<&'a [u8]>,
    receipt_custody_context: SeedRecipientReceiptCustodyContext320,
    receipt_custody_record_bytes: &'a [u8],
}

struct BoundedCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BoundedCursor<'a> {
    fn new(
        bytes: &'a [u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
        if bytes.len() > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
            return Err(
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ResourceLimit(
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
    ) -> Result<&'a [u8], PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
        let end = self.offset.checked_add(byte_length).ok_or(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ResourceLimit(
                field,
            ),
        )?;
        if end > self.bytes.len() {
            return Err(
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                    field,
                ),
            );
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_unsigned8(
        &mut self,
        field: &'static str,
    ) -> Result<u8, PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
        Ok(self.read_exact(1, field)?[0])
    }

    fn read_unsigned16(
        &mut self,
        field: &'static str,
    ) -> Result<u16, PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
        Ok(u16::from_le_bytes(
            self.read_exact(size_of::<u16>(), field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                        field,
                    )
                })?,
        ))
    }

    fn read_unsigned32(
        &mut self,
        field: &'static str,
    ) -> Result<usize, PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
        let value = u32::from_le_bytes(
            self.read_exact(size_of::<u32>(), field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                        field,
                    )
                })?,
        );
        usize::try_from(value).map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ResourceLimit(
                field,
            )
        })
    }

    fn read_hash512(
        &mut self,
        field: &'static str,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
        Ok(Hash512::from_bytes(
            self.read_exact(Hash512::BYTE_LENGTH, field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                        field,
                    )
                })?,
        ))
    }

    fn read_bounded_bytes(
        &mut self,
        maximum_byte_length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
        let byte_length = self.read_unsigned32(field)?;
        if byte_length == 0 || byte_length > maximum_byte_length {
            return Err(
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ResourceLimit(
                    field,
                ),
            );
        }
        self.read_exact(byte_length, field)
    }

    fn require_magic(
        &mut self,
        expected: &[u8; 4],
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
        if self.read_exact(expected.len(), field)? != expected {
            return Err(
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                    field,
                ),
            );
        }
        Ok(())
    }

    fn require_version(
        &mut self,
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
        if self.read_unsigned16(field)? != CODEC_VERSION {
            return Err(
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                    field,
                ),
            );
        }
        Ok(())
    }

    fn require_complete(
        &self,
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
        if self.offset != self.bytes.len() {
            return Err(
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                    field,
                ),
            );
        }
        Ok(())
    }
}

fn read_receipt_custody_context(
    cursor: &mut BoundedCursor<'_>,
) -> Result<
    SeedRecipientReceiptCustodyContext320,
    PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320,
> {
    Ok(SeedRecipientReceiptCustodyContext320 {
        parameter_identity: cursor.read_hash512("receipt parameter identity")?,
        preparation_context_identity: cursor
            .read_hash512("receipt preparation-context identity")?,
        root_terminal_identity: cursor.read_hash512("receipt root-terminal identity")?,
        preparation_attempt_ordinal: cursor.read_unsigned16("receipt preparation attempt")?,
        participant_count: cursor.read_unsigned16("receipt participant count")?,
        recipient_position: cursor.read_unsigned16("receipt recipient position")?,
    })
}

fn parse_open_context_request<'a>(
    cursor: &mut BoundedCursor<'a>,
) -> Result<
    OpenContextRequest320<'a>,
    PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320,
> {
    let parameter_identity = cursor.read_hash512("parameter identity")?;
    let endorser_position = cursor.read_unsigned16("endorser position")?;
    let preparation_context_bytes = cursor.read_bounded_bytes(
        MAXIMUM_PREPARATION_CONTEXT_BYTE_LENGTH,
        "preparation context",
    )?;
    let roster_bytes = cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "roster")?;
    let root_package_count = usize::from(cursor.read_unsigned16("root-package count")?);
    if root_package_count == 0 || root_package_count > MAXIMUM_PARTICIPANT_COUNT {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ResourceLimit(
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
    let receipt_count = usize::from(cursor.read_unsigned16("receipt count")?);
    if receipt_count == 0 || receipt_count > MAXIMUM_PARTICIPANT_COUNT {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ResourceLimit(
                "receipt count",
            ),
        );
    }
    let mut receipt_envelope_bytes = Vec::with_capacity(receipt_count);
    for _ in 0..receipt_count {
        receipt_envelope_bytes.push(
            cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "receipt envelope")?,
        );
    }
    let receipt_custody_context = read_receipt_custody_context(cursor)?;
    let receipt_custody_record_bytes =
        cursor.read_bounded_bytes(MAXIMUM_COPIED_BUFFER_BYTE_LENGTH, "receipt-custody record")?;
    cursor.require_complete("open-context trailing bytes")?;
    Ok(OpenContextRequest320 {
        parameter_identity,
        endorser_position,
        preparation_context_bytes,
        roster_bytes,
        root_packages,
        root_terminal_certificate_bytes,
        receipt_envelope_bytes,
        receipt_custody_context,
        receipt_custody_record_bytes,
    })
}

fn verify_open_context(
    request: OpenContextRequest320<'_>,
) -> Result<
    VerifiedTerminalEndorsementContext320,
    PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320,
> {
    let preparation_context = TallyPreparationContext::from_canonical_bytes(
        request.preparation_context_bytes,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
            "preparation context",
        )
    })?;
    let roster =
        Roster::decode(request.roster_bytes, &CanonicalDecodeLimits::default()).map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                "roster",
            )
        })?;
    if roster.encode().map_err(|_| {
        PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
            "roster",
        )
    })? != request.roster_bytes
    {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                "noncanonical roster",
            ),
        );
    }
    if roster.entries.len() != usize::from(preparation_context.participant_count())
        || request.root_packages.len() != roster.entries.len()
        || request.receipt_envelope_bytes.len() != roster.entries.len()
        || usize::from(request.endorser_position) >= roster.entries.len()
        || roster.entries[usize::from(request.endorser_position)].roster_position
            != request.endorser_position
        || roster.roster_hash().map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                "roster identity",
            )
        })? != preparation_context.roster_hash()
    {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                "roster scope",
            ),
        );
    }
    let root_inventory = verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
        request.parameter_identity,
        preparation_context,
        &roster,
        &request.root_packages,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
            "root inventory",
        )
    })?;
    let root_terminal = verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
        root_inventory,
        &roster,
        request.root_terminal_certificate_bytes,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
            "root terminal",
        )
    })?;
    let root_terminal_identity = root_terminal.identity().map_err(|_| {
        PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
            "root-terminal identity",
        )
    })?;
    if request.receipt_custody_context.parameter_identity != request.parameter_identity
        || request.receipt_custody_context.preparation_context_identity
            != preparation_context.identity()
        || request.receipt_custody_context.root_terminal_identity != root_terminal_identity
        || request.receipt_custody_context.preparation_attempt_ordinal
            != PREPARATION_ATTEMPT_ORDINAL
        || request.receipt_custody_context.participant_count
            != preparation_context.participant_count()
        || request.receipt_custody_context.recipient_position != request.endorser_position
    {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ContextMismatch(
                "receipt-custody context",
            ),
        );
    }
    let retained_local_receipt = verify_completed_seed_recipient_receipt_custody_320(
        request.receipt_custody_record_bytes,
        request.receipt_custody_context,
        &root_terminal,
        &roster,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ReceiptCustody(
            "completed receipt record",
        )
    })?;
    let receipt_inventory = verify_pseudorandom_zero_sharing_seed_recipient_receipt_inventory_320(
        &root_terminal,
        &roster,
        &request.receipt_envelope_bytes,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
            "receipt inventory",
        )
    })?;
    let prepared_endorsement =
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
            root_terminal,
            receipt_inventory,
            &roster,
            &retained_local_receipt.receipt,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                "retained local receipt match",
            )
        })?;
    Ok(VerifiedTerminalEndorsementContext320 {
        custody_context: request.receipt_custody_context,
        prepared_endorsement,
        roster,
        ordered_receipt_envelope_bytes: request
            .receipt_envelope_bytes
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        retained_local_receipt_body_identity: retained_local_receipt.receipt_body_identity,
        retained_local_receipt_envelope_identity: retained_local_receipt.receipt_envelope_identity,
    })
}

fn retain_verified_context(
    context: VerifiedTerminalEndorsementContext320,
) -> Result<u32, PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
    VERIFIED_TERMINAL_ENDORSEMENT_CONTEXTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        if registry.retained.is_some() {
            return Err(
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ResourceLimit(
                    "retained context count",
                ),
            );
        }
        let handle = registry.next_handle;
        if handle == 0 {
            return Err(
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ResourceLimit(
                    "context handle",
                ),
            );
        }
        registry.next_handle = handle.checked_add(1).ok_or(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ResourceLimit(
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
        &VerifiedTerminalEndorsementContext320,
    ) -> Result<
        ResultValue,
        PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320,
    >,
) -> Result<ResultValue, PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
    VERIFIED_TERMINAL_ENDORSEMENT_CONTEXTS.with(|registry| {
        let registry = registry.borrow();
        let context = registry
            .retained
            .as_ref()
            .filter(|(retained_handle, _context)| *retained_handle == handle)
            .map(|(_retained_handle, context)| context)
            .ok_or(
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ContextUnavailable,
            )?;
        operation(context)
    })
}

fn close_verified_context(
    handle: u32,
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
    VERIFIED_TERMINAL_ENDORSEMENT_CONTEXTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        if !matches!(registry.retained, Some((retained_handle, _)) if retained_handle == handle) {
            return Err(
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ContextUnavailable,
            );
        }
        registry.retained = None;
        Ok(())
    })
}

fn require_matching_bytes(
    actual: &[u8],
    expected: &[u8],
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
    if actual != expected {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PreparedMismatch(
                field,
            ),
        );
    }
    Ok(())
}

fn require_matching_hash(
    actual: Hash512,
    expected: Hash512,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
    if actual != expected {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PreparedMismatch(
                field,
            ),
        );
    }
    Ok(())
}

fn verify_prepared_inventory(
    cursor: &mut BoundedCursor<'_>,
    context: &VerifiedTerminalEndorsementContext320,
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
    let authorization_body =
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_signature_320(
            &context.prepared_endorsement,
            &context.roster,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                "prepared endorsement",
            )
        })?;
    let authorization_body_bytes = authorization_body.canonical_bytes().map_err(|_| {
        PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
            "endorsement authorization body",
        )
    })?;
    require_matching_bytes(
        cursor.read_bounded_bytes(
            MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
            "endorsement authorization body",
        )?,
        &authorization_body_bytes,
        "endorsement authorization body",
    )?;
    let inventory_body_bytes = context
        .prepared_endorsement
        .receipt_inventory()
        .body()
        .canonical_bytes()
        .map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                "receipt-inventory body",
            )
        })?;
    require_matching_bytes(
        cursor.read_bounded_bytes(
            MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
            "verified receipt-inventory body",
        )?,
        &inventory_body_bytes,
        "verified receipt-inventory body",
    )?;
    require_matching_hash(
        cursor.read_hash512("verified receipt-inventory identity")?,
        context
            .prepared_endorsement
            .receipt_inventory()
            .identity()
            .map_err(|_| {
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                    "receipt-inventory identity",
                )
            })?,
        "verified receipt-inventory identity",
    )?;
    let receipt_count = usize::from(cursor.read_unsigned16("ordered receipt count")?);
    if receipt_count != context.ordered_receipt_envelope_bytes.len() {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PreparedMismatch(
                "ordered receipt count",
            ),
        );
    }
    for expected_receipt_envelope_bytes in &context.ordered_receipt_envelope_bytes {
        require_matching_bytes(
            cursor.read_bounded_bytes(
                MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
                "ordered receipt envelope",
            )?,
            expected_receipt_envelope_bytes,
            "ordered receipt envelope",
        )?;
    }
    require_matching_hash(
        cursor.read_hash512("retained local receipt-body identity")?,
        context.retained_local_receipt_body_identity,
        "retained local receipt-body identity",
    )?;
    require_matching_hash(
        cursor.read_hash512("retained local receipt-envelope identity")?,
        context.retained_local_receipt_envelope_identity,
        "retained local receipt-envelope identity",
    )?;
    let terminal_body = context.prepared_endorsement.terminal_body();
    let terminal_body_bytes = terminal_body.canonical_bytes().map_err(|_| {
        PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
            "terminal body",
        )
    })?;
    require_matching_bytes(
        cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "terminal body")?,
        &terminal_body_bytes,
        "terminal body",
    )?;
    require_matching_hash(
        cursor.read_hash512("terminal identity")?,
        terminal_body.identity().map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                "terminal identity",
            )
        })?,
        "terminal identity",
    )
}

fn verify_validation_context(
    cursor: &mut BoundedCursor<'_>,
    context: &VerifiedTerminalEndorsementContext320,
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
    if cursor.read_hash512("validation parameter identity")?
        != context.custody_context.parameter_identity
        || cursor.read_unsigned16("validation participant count")?
            != context.custody_context.participant_count
        || cursor.read_unsigned16("validation preparation attempt")?
            != context.custody_context.preparation_attempt_ordinal
        || cursor.read_hash512("validation preparation-context identity")?
            != context.custody_context.preparation_context_identity
        || cursor.read_unsigned16("validation endorser position")?
            != context.custody_context.recipient_position
        || cursor.read_hash512("validation root-terminal identity")?
            != context.custody_context.root_terminal_identity
    {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ContextMismatch(
                "validation context",
            ),
        );
    }
    Ok(())
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
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
    output.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| {
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ResourceLimit(
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
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
    append_unsigned32(output, value.len())?;
    output.extend_from_slice(value);
    if output.len() > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ResourceLimit(
                "response byte length",
            ),
        );
    }
    Ok(())
}

fn encode_failure_response(
    error: &PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320,
) -> Zeroizing<Vec<u8>> {
    let mut bytes = response_header(FAILURE_STATUS);
    append_unsigned16(&mut bytes, error.response_code());
    bytes
}

fn encode_open_response(
    handle: u32,
    verification_key: &[u8; ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH],
) -> Zeroizing<Vec<u8>> {
    let mut bytes = response_header(OPEN_CONTEXT_STATUS);
    bytes.extend_from_slice(&handle.to_le_bytes());
    bytes.extend_from_slice(verification_key);
    bytes
}

fn append_prepared_inventory(
    bytes: &mut Vec<u8>,
    context: &VerifiedTerminalEndorsementContext320,
) -> Result<(), PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320> {
    let authorization_body =
        prepare_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_signature_320(
            &context.prepared_endorsement,
            &context.roster,
        )
        .map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                "prepared endorsement",
            )
        })?;
    append_bounded_bytes(
        bytes,
        &authorization_body.canonical_bytes().map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                "endorsement authorization body",
            )
        })?,
    )?;
    let receipt_inventory = context.prepared_endorsement.receipt_inventory();
    append_bounded_bytes(
        bytes,
        &receipt_inventory.body().canonical_bytes().map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                "receipt-inventory body",
            )
        })?,
    )?;
    bytes.extend_from_slice(
        receipt_inventory
            .identity()
            .map_err(|_| {
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                    "receipt-inventory identity",
                )
            })?
            .as_bytes(),
    );
    append_unsigned16(
        bytes,
        u16::try_from(context.ordered_receipt_envelope_bytes.len()).map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::ResourceLimit(
                "ordered receipt count",
            )
        })?,
    );
    for receipt_envelope_bytes in &context.ordered_receipt_envelope_bytes {
        append_bounded_bytes(bytes, receipt_envelope_bytes)?;
    }
    bytes.extend_from_slice(context.retained_local_receipt_body_identity.as_bytes());
    bytes.extend_from_slice(context.retained_local_receipt_envelope_identity.as_bytes());
    let terminal_body = context.prepared_endorsement.terminal_body();
    append_bounded_bytes(
        bytes,
        &terminal_body.canonical_bytes().map_err(|_| {
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                "terminal body",
            )
        })?,
    )?;
    bytes.extend_from_slice(
        terminal_body
            .identity()
            .map_err(|_| {
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::PublicVerification(
                    "terminal identity",
                )
            })?
            .as_bytes(),
    );
    Ok(())
}

fn encode_prepared_response(
    context: &VerifiedTerminalEndorsementContext320,
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320>
{
    let mut bytes = response_header(PREPARED_ENDORSEMENT_STATUS);
    append_prepared_inventory(&mut bytes, context)?;
    Ok(bytes)
}

fn encode_complete_response(
    endorsement_envelope_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320>
{
    if endorsement_envelope_bytes.len()
        != PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH
    {
        return Err(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::SignatureMismatch,
        );
    }
    let mut bytes = response_header(COMPLETE_ENDORSEMENT_STATUS);
    append_bounded_bytes(&mut bytes, endorsement_envelope_bytes)?;
    Ok(bytes)
}

fn parse_request(
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320>
{
    let mut cursor = BoundedCursor::new(bytes)?;
    cursor.require_magic(REQUEST_MAGIC, "request magic")?;
    cursor.require_version("request version")?;
    let operation = cursor.read_unsigned8("operation")?;
    match operation {
        OPEN_CONTEXT_OPERATION => {
            let verified = verify_open_context(parse_open_context_request(&mut cursor)?)?;
            let verification_key = verified.roster.entries
                [usize::from(verified.custody_context.recipient_position)]
            .signing_verification_key;
            let handle = retain_verified_context(verified)?;
            Ok(encode_open_response(handle, &verification_key))
        }
        PREPARE_ENDORSEMENT_OPERATION => {
            let handle = u32::try_from(cursor.read_unsigned32("context handle")?).map_err(|_| {
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                    "context handle",
                )
            })?;
            cursor.require_complete("prepare-endorsement trailing bytes")?;
            with_verified_context(handle, encode_prepared_response)
        }
        COMPLETE_ENDORSEMENT_OPERATION => {
            let handle = u32::try_from(cursor.read_unsigned32("context handle")?).map_err(|_| {
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                    "context handle",
                )
            })?;
            with_verified_context(handle, |context| {
                verify_prepared_inventory(&mut cursor, context)?;
                let signature = cursor
                    .read_exact(ML_DSA_65_SIGNATURE_BYTE_LENGTH, "endorsement signature")?
                    .try_into()
                    .map_err(|_| {
                        PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                            "endorsement signature",
                        )
                    })?;
                cursor.require_complete("complete-endorsement trailing bytes")?;
                let produced = complete_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_signature_320(
                    context.prepared_endorsement.clone(),
                    &context.roster,
                    signature,
                )
                .map_err(|_| {
                    PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::SignatureMismatch
                })?;
                encode_complete_response(produced.endorsement_envelope_bytes())
            })
        }
        VALIDATE_ENDORSEMENT_OPERATION => {
            let handle = u32::try_from(cursor.read_unsigned32("context handle")?).map_err(|_| {
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                    "context handle",
                )
            })?;
            with_verified_context(handle, |context| {
                verify_validation_context(&mut cursor, context)?;
                verify_prepared_inventory(&mut cursor, context)?;
                let has_endorsement_envelope =
                    cursor.read_unsigned8("endorsement-envelope presence")?;
                match has_endorsement_envelope {
                    0 => {}
                    1 => {
                        let endorsement_envelope_bytes = cursor.read_bounded_bytes(
                            MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
                            "endorsement envelope",
                        )?;
                        verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_endorsement_320(
                            &context.prepared_endorsement,
                            &context.roster,
                            endorsement_envelope_bytes,
                        )
                        .map_err(|_| {
                            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::SignatureMismatch
                        })?;
                    }
                    _ => {
                        return Err(
                            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                                "endorsement-envelope presence",
                            ),
                        );
                    }
                }
                cursor.require_complete("validate-endorsement trailing bytes")?;
                Ok(response_header(VALIDATION_STATUS))
            })
        }
        CLOSE_CONTEXT_OPERATION => {
            let handle = u32::try_from(cursor.read_unsigned32("context handle")?).map_err(|_| {
                PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                    "context handle",
                )
            })?;
            cursor.require_complete("close-context trailing bytes")?;
            close_verified_context(handle)?;
            Ok(response_header(CLOSED_CONTEXT_STATUS))
        }
        _ => Err(
            PseudorandomZeroSharingSeedReceiptTerminalEndorsementKernelError320::MalformedRequest(
                "operation",
            ),
        ),
    }
}

pub(crate) fn run_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_kernel_320(
    input: &[u8],
) -> Zeroizing<Vec<u8>> {
    match parse_request(input) {
        Ok(response) => response,
        Err(error) => encode_failure_response(&error),
    }
}

#[cfg(test)]
pub(crate) fn clear_pseudorandom_zero_sharing_seed_receipt_terminal_endorsement_contexts_for_test_320()
 {
    VERIFIED_TERMINAL_ENDORSEMENT_CONTEXTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.retained = None;
        registry.next_handle = 1;
    });
}
