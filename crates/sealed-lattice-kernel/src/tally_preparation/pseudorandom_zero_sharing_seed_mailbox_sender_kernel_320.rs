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
    pseudorandom_zero_sharing_seed_catalog_root_terminal_320::{
        RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
        verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320,
    },
    pseudorandom_zero_sharing_seed_catalog_signature_320::ML_DSA_65_SIGNATURE_BYTE_LENGTH,
    pseudorandom_zero_sharing_seed_mailbox_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MAXIMUM_PLAINTEXT_CHUNK_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH,
        PseudorandomZeroSharingSeedMailboxHeaderBody320,
        PseudorandomZeroSharingSeedMailboxManifestBody320,
        PseudorandomZeroSharingSeedMailboxSealer320,
        PseudorandomZeroSharingSeedMailboxSignatureBody320,
        PseudorandomZeroSharingSignedSeedMailboxManifestEnvelope320,
        pseudorandom_zero_sharing_seed_mailbox_manifest_body_byte_length,
        verify_pseudorandom_zero_sharing_seed_mailbox_sender_carrier_320,
    },
    pseudorandom_zero_sharing_seed_master_custody_320::{
        SeedCatalogSourceCustodyContext320, VerifiedSeedCatalogDeliverySources320,
        verify_and_retain_seed_catalog_delivery_sources_320,
    },
};

const REQUEST_MAGIC: &[u8; 4] = b"SLMQ";
const RESPONSE_MAGIC: &[u8; 4] = b"SLMR";
const CODEC_VERSION: u16 = 1;
const OPEN_CONTEXT_OPERATION: u8 = 1;
const PREPARE_CARRIER_OPERATION: u8 = 2;
const COMPLETE_CARRIER_OPERATION: u8 = 3;
const VALIDATE_CARRIER_OPERATION: u8 = 4;
const CLOSE_CONTEXT_OPERATION: u8 = 5;
const FAILURE_STATUS: u8 = 0;
const OPEN_CONTEXT_STATUS: u8 = 1;
const PREPARED_CARRIER_STATUS: u8 = 2;
const COMPLETE_CARRIER_STATUS: u8 = 3;
const VALIDATION_STATUS: u8 = 4;
const CLOSED_CONTEXT_STATUS: u8 = 5;
const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const MAXIMUM_COPIED_BUFFER_BYTE_LENGTH: usize = 8 * 1024 * 1024;
const MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH: usize = 1024 * 1024;
const MAXIMUM_PREPARATION_CONTEXT_BYTE_LENGTH: usize = 4096;
const MAXIMUM_PARTICIPANT_COUNT: usize = 32;
const MAXIMUM_MAILBOX_CHUNK_COUNT: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedMailboxSenderKernelError320 {
    MalformedRequest(&'static str),
    ResourceLimit(&'static str),
    ContextMismatch(&'static str),
    PublicVerification(&'static str),
    StreamProduction(&'static str),
    CarrierMismatch(&'static str),
    ContextUnavailable,
    SignatureMismatch,
    SourceCustody(&'static str),
}

impl PseudorandomZeroSharingSeedMailboxSenderKernelError320 {
    const fn response_code(&self) -> u16 {
        match self {
            Self::MalformedRequest(_) => 1,
            Self::ResourceLimit(_) => 2,
            Self::ContextMismatch(_) => 3,
            Self::PublicVerification(_) => 4,
            Self::StreamProduction(_) => 5,
            Self::CarrierMismatch(_) => 6,
            Self::ContextUnavailable => 7,
            Self::SignatureMismatch => 8,
            Self::SourceCustody(_) => 9,
        }
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedMailboxSenderKernelError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedRequest(field) => {
                write!(
                    formatter,
                    "seed-mailbox sender kernel malformed request: {field}"
                )
            }
            Self::ResourceLimit(field) => {
                write!(
                    formatter,
                    "seed-mailbox sender kernel resource limit: {field}"
                )
            }
            Self::ContextMismatch(field) => {
                write!(
                    formatter,
                    "seed-mailbox sender kernel context mismatch: {field}"
                )
            }
            Self::PublicVerification(field) => write!(
                formatter,
                "seed-mailbox sender kernel public verification failed: {field}"
            ),
            Self::StreamProduction(field) => {
                write!(
                    formatter,
                    "seed-mailbox sender kernel production failed: {field}"
                )
            }
            Self::CarrierMismatch(field) => {
                write!(
                    formatter,
                    "seed-mailbox sender kernel carrier mismatch: {field}"
                )
            }
            Self::ContextUnavailable => {
                formatter.write_str("seed-mailbox sender kernel context is unavailable")
            }
            Self::SignatureMismatch => {
                formatter.write_str("seed-mailbox sender kernel signature is invalid")
            }
            Self::SourceCustody(field) => {
                write!(
                    formatter,
                    "seed-mailbox sender kernel source custody failed: {field}"
                )
            }
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedMailboxSenderKernelError320 {}

struct VerifiedSenderContext320 {
    delivery_sources: VerifiedSeedCatalogDeliverySources320,
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    roster: Roster,
    root_terminal: RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    sender_position: u16,
}

struct VerifiedSenderContextRegistry320 {
    next_handle: u32,
    retained: Option<(u32, VerifiedSenderContext320)>,
}

impl Default for VerifiedSenderContextRegistry320 {
    fn default() -> Self {
        Self {
            next_handle: 1,
            retained: None,
        }
    }
}

thread_local! {
    static VERIFIED_SENDER_CONTEXTS: RefCell<VerifiedSenderContextRegistry320> =
        RefCell::new(VerifiedSenderContextRegistry320::default());
}

#[derive(Clone, Copy)]
struct StreamContext320 {
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    root_terminal_identity: Hash512,
    participant_count: u16,
    preparation_attempt_ordinal: u16,
    sender_position: u16,
    recipient_position: u16,
}

struct OpenContextRequest320<'a> {
    parameter_identity: Hash512,
    sender_position: u16,
    preparation_context_bytes: &'a [u8],
    roster_bytes: &'a [u8],
    root_packages: Vec<PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320<'a>>,
    root_terminal_certificate_bytes: &'a [u8],
    source_custody_context: SeedCatalogSourceCustodyContext320,
    source_custody_record_bytes: &'a [u8],
}

struct PreparedCarrier320 {
    header_bytes: Vec<u8>,
    manifest_bytes: Vec<u8>,
    signature_body_bytes: Vec<u8>,
    encrypted_chunks: Vec<Zeroizing<Vec<u8>>>,
}

struct CarrierParts320<'a> {
    header_bytes: &'a [u8],
    manifest_bytes: &'a [u8],
    signature_envelope_bytes: &'a [u8],
    encrypted_chunks: Vec<&'a [u8]>,
}

struct ExpectedCarrierGeometry320 {
    source_payload_byte_length: usize,
    total_carrier_byte_length: usize,
    header_byte_length: usize,
    manifest_byte_length: usize,
    signature_envelope_byte_length: usize,
    encrypted_chunk_byte_lengths: Vec<usize>,
}

struct BoundedCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BoundedCursor<'a> {
    fn new(
        bytes: &'a [u8],
    ) -> Result<Self, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
        if bytes.len() > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
            return Err(
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(
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
    ) -> Result<&'a [u8], PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
        let end = self
            .offset
            .checked_add(byte_length)
            .ok_or(PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(field))?;
        if end > self.bytes.len() {
            return Err(
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest(field),
            );
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_unsigned8(
        &mut self,
        field: &'static str,
    ) -> Result<u8, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
        Ok(self.read_exact(1, field)?[0])
    }

    fn read_unsigned16(
        &mut self,
        field: &'static str,
    ) -> Result<u16, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
        Ok(u16::from_le_bytes(
            self.read_exact(size_of::<u16>(), field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest(field)
                })?,
        ))
    }

    fn read_unsigned32(
        &mut self,
        field: &'static str,
    ) -> Result<usize, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
        let value = u32::from_le_bytes(
            self.read_exact(size_of::<u32>(), field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest(field)
                })?,
        );
        usize::try_from(value).map_err(|_| {
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(field)
        })
    }

    fn read_hash512(
        &mut self,
        field: &'static str,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
        Ok(Hash512::from_bytes(
            self.read_exact(Hash512::BYTE_LENGTH, field)?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest(field)
                })?,
        ))
    }

    fn read_bounded_bytes(
        &mut self,
        maximum_byte_length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
        let byte_length = self.read_unsigned32(field)?;
        if byte_length == 0 || byte_length > maximum_byte_length {
            return Err(
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(field),
            );
        }
        self.read_exact(byte_length, field)
    }

    fn require_magic(
        &mut self,
        expected: &[u8; 4],
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
        if self.read_exact(expected.len(), field)? != expected {
            return Err(
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest(field),
            );
        }
        Ok(())
    }

    fn require_version(
        &mut self,
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
        if self.read_unsigned16(field)? != CODEC_VERSION {
            return Err(
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest(field),
            );
        }
        Ok(())
    }

    fn require_complete(
        &self,
        field: &'static str,
    ) -> Result<(), PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
        if self.offset != self.bytes.len() {
            return Err(
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest(field),
            );
        }
        Ok(())
    }
}

fn read_source_custody_context(
    cursor: &mut BoundedCursor<'_>,
) -> Result<
    SeedCatalogSourceCustodyContext320,
    PseudorandomZeroSharingSeedMailboxSenderKernelError320,
> {
    Ok(SeedCatalogSourceCustodyContext320 {
        parameter_identity: cursor.read_hash512("source parameter identity")?,
        roster_identity: cursor.read_hash512("source roster identity")?,
        action_context_identity: cursor.read_hash512("source action-context identity")?,
        preparation_context_identity: cursor.read_hash512("source preparation-context identity")?,
        catalog_compiler_identity: cursor.read_hash512("source catalog-compiler identity")?,
        state_predecessor_identity: cursor.read_hash512("source state-predecessor identity")?,
        preparation_attempt_ordinal: cursor.read_unsigned16("source preparation attempt")?,
        participant_count: cursor.read_unsigned16("source participant count")?,
        participant_position: cursor.read_unsigned16("source participant position")?,
    })
}

fn parse_open_context_request<'a>(
    cursor: &mut BoundedCursor<'a>,
) -> Result<OpenContextRequest320<'a>, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    let parameter_identity = cursor.read_hash512("parameter identity")?;
    let sender_position = cursor.read_unsigned16("sender position")?;
    let preparation_context_bytes = cursor.read_bounded_bytes(
        MAXIMUM_PREPARATION_CONTEXT_BYTE_LENGTH,
        "preparation context",
    )?;
    let roster_bytes = cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "roster")?;
    let root_package_count = usize::from(cursor.read_unsigned16("root-package count")?);
    if root_package_count == 0 || root_package_count > MAXIMUM_PARTICIPANT_COUNT {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(
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
    let source_custody_context = read_source_custody_context(cursor)?;
    let source_custody_record_bytes =
        cursor.read_bounded_bytes(MAXIMUM_COPIED_BUFFER_BYTE_LENGTH, "source-custody record")?;
    cursor.require_complete("open-context trailing bytes")?;
    Ok(OpenContextRequest320 {
        parameter_identity,
        sender_position,
        preparation_context_bytes,
        roster_bytes,
        root_packages,
        root_terminal_certificate_bytes,
        source_custody_context,
        source_custody_record_bytes,
    })
}

fn verify_open_context(
    request: OpenContextRequest320<'_>,
) -> Result<VerifiedSenderContext320, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    let preparation_context = TallyPreparationContext::from_canonical_bytes(
        request.preparation_context_bytes,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::PublicVerification(
            "preparation context",
        )
    })?;
    let roster =
        Roster::decode(request.roster_bytes, &CanonicalDecodeLimits::default()).map_err(|_| {
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::PublicVerification("roster")
        })?;
    if roster.encode().map_err(|_| {
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::PublicVerification("roster")
    })? != request.roster_bytes
    {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::PublicVerification(
                "noncanonical roster",
            ),
        );
    }
    if roster.entries.len() != usize::from(preparation_context.participant_count())
        || request.root_packages.len() != roster.entries.len()
        || usize::from(request.sender_position) >= roster.entries.len()
        || roster.entries[usize::from(request.sender_position)].roster_position
            != request.sender_position
        || roster.roster_hash().map_err(|_| {
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::PublicVerification(
                "roster identity",
            )
        })? != preparation_context.roster_hash()
    {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::PublicVerification(
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
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::PublicVerification("root inventory")
    })?;
    let root_terminal = verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
        root_inventory,
        &roster,
        request.root_terminal_certificate_bytes,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::PublicVerification("root terminal")
    })?;
    if request.source_custody_context.parameter_identity != request.parameter_identity
        || request.source_custody_context.roster_identity != preparation_context.roster_hash()
        || request.source_custody_context.preparation_context_identity
            != preparation_context.identity()
        || request.source_custody_context.preparation_attempt_ordinal != PREPARATION_ATTEMPT_ORDINAL
        || request.source_custody_context.participant_count
            != preparation_context.participant_count()
        || request.source_custody_context.participant_position != request.sender_position
    {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ContextMismatch(
                "source-custody context",
            ),
        );
    }
    let delivery_sources = verify_and_retain_seed_catalog_delivery_sources_320(
        request.source_custody_record_bytes,
        request.source_custody_context,
        preparation_context,
        &root_terminal,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::SourceCustody(
            "completed source record",
        )
    })?;
    Ok(VerifiedSenderContext320 {
        delivery_sources,
        parameter_identity: request.parameter_identity,
        preparation_context,
        roster,
        root_terminal,
        sender_position: request.sender_position,
    })
}

fn retain_verified_context(
    context: VerifiedSenderContext320,
) -> Result<u32, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    VERIFIED_SENDER_CONTEXTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        if registry.retained.is_some() {
            return Err(
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(
                    "retained context count",
                ),
            );
        }
        let handle = registry.next_handle;
        if handle == 0 {
            return Err(
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(
                    "context handle",
                ),
            );
        }
        registry.next_handle = handle.checked_add(1).ok_or(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit("context handle"),
        )?;
        registry.retained = Some((handle, context));
        Ok(handle)
    })
}

fn with_verified_context<ResultValue>(
    handle: u32,
    operation: impl FnOnce(
        &VerifiedSenderContext320,
    ) -> Result<
        ResultValue,
        PseudorandomZeroSharingSeedMailboxSenderKernelError320,
    >,
) -> Result<ResultValue, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    VERIFIED_SENDER_CONTEXTS.with(|registry| {
        let registry = registry.borrow();
        let context = registry
            .retained
            .as_ref()
            .filter(|(retained_handle, _context)| *retained_handle == handle)
            .map(|(_retained_handle, context)| context)
            .ok_or(PseudorandomZeroSharingSeedMailboxSenderKernelError320::ContextUnavailable)?;
        operation(context)
    })
}

fn close_verified_context(
    handle: u32,
) -> Result<(), PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    VERIFIED_SENDER_CONTEXTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        if !matches!(registry.retained, Some((retained_handle, _)) if retained_handle == handle) {
            return Err(PseudorandomZeroSharingSeedMailboxSenderKernelError320::ContextUnavailable);
        }
        registry.retained = None;
        Ok(())
    })
}

fn read_stream_context(
    cursor: &mut BoundedCursor<'_>,
) -> Result<StreamContext320, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    Ok(StreamContext320 {
        parameter_identity: cursor.read_hash512("stream parameter identity")?,
        participant_count: cursor.read_unsigned16("stream participant count")?,
        preparation_attempt_ordinal: cursor
            .read_unsigned16("stream preparation-attempt ordinal")?,
        preparation_context_identity: cursor.read_hash512("stream preparation-context identity")?,
        root_terminal_identity: cursor.read_hash512("stream root-terminal identity")?,
        sender_position: cursor.read_unsigned16("stream sender position")?,
        recipient_position: cursor.read_unsigned16("stream recipient position")?,
    })
}

fn require_stream_context(
    verified: &VerifiedSenderContext320,
    stream: StreamContext320,
) -> Result<(), PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    if stream.parameter_identity != verified.parameter_identity {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ContextMismatch(
                "parameter identity",
            ),
        );
    }
    if stream.participant_count != verified.preparation_context.participant_count() {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ContextMismatch(
                "participant count",
            ),
        );
    }
    if stream.preparation_attempt_ordinal != PREPARATION_ATTEMPT_ORDINAL {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ContextMismatch(
                "preparation-attempt ordinal",
            ),
        );
    }
    if stream.preparation_context_identity != verified.preparation_context.identity() {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ContextMismatch(
                "preparation-context identity",
            ),
        );
    }
    let terminal_identity = verified.root_terminal.identity().map_err(|_| {
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::PublicVerification(
            "root-terminal identity",
        )
    })?;
    if stream.root_terminal_identity != terminal_identity {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ContextMismatch(
                "root-terminal identity",
            ),
        );
    }
    if stream.sender_position != verified.sender_position
        || stream.recipient_position >= stream.participant_count
        || stream.recipient_position == stream.sender_position
    {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ContextMismatch(
                "stream endpoints",
            ),
        );
    }
    Ok(())
}

fn produce_prepared_carrier(
    verified: &VerifiedSenderContext320,
    stream: StreamContext320,
    descriptor_bytes: &[u8],
    encapsulation_randomness_bytes: &[u8],
) -> Result<PreparedCarrier320, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    require_stream_context(verified, stream)?;
    let encapsulation_randomness =
        Zeroizing::new(encapsulation_randomness_bytes.try_into().map_err(|_| {
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest(
                "encapsulation randomness",
            )
        })?);
    let source_payload = verified
        .delivery_sources
        .payload_for_recipient(stream.recipient_position)
        .ok_or(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::SourceCustody(
                "canonical recipient payload",
            ),
        )?;
    let mut sealer = PseudorandomZeroSharingSeedMailboxSealer320::new(
        &verified.root_terminal,
        &verified.roster,
        stream.sender_position,
        stream.recipient_position,
        descriptor_bytes,
        &encapsulation_randomness,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::StreamProduction("header")
    })?;
    let expected_payload_byte_length = usize::try_from(
        sealer.header().delivery_descriptor().payload_byte_length(),
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(
            "source payload byte length",
        )
    })?;
    if source_payload.len() != expected_payload_byte_length {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::StreamProduction(
                "source payload byte length",
            ),
        );
    }
    let header_bytes = sealer.header().canonical_bytes().map_err(|_| {
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::StreamProduction("header encoding")
    })?;
    let mut encrypted_chunks = Vec::new();
    for plaintext_chunk in source_payload
        .chunks(PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MAXIMUM_PLAINTEXT_CHUNK_BYTE_LENGTH)
    {
        encrypted_chunks.push(
            sealer
                .seal_next_plaintext_chunk(plaintext_chunk)
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMailboxSenderKernelError320::StreamProduction(
                        "encrypted chunk",
                    )
                })?,
        );
    }
    let manifest = sealer.finish().map_err(|_| {
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::StreamProduction("manifest")
    })?;
    let manifest_bytes = manifest.canonical_bytes().map_err(|_| {
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::StreamProduction(
            "manifest encoding",
        )
    })?;
    let header =
        PseudorandomZeroSharingSeedMailboxHeaderBody320::from_canonical_bytes(&header_bytes)
            .map_err(|_| {
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::StreamProduction(
                    "header reconstruction",
                )
            })?;
    let signature_body_bytes =
        PseudorandomZeroSharingSeedMailboxSignatureBody320::new(&header, &manifest)
            .and_then(PseudorandomZeroSharingSeedMailboxSignatureBody320::canonical_bytes)
            .map_err(|_| {
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::StreamProduction(
                    "signature body",
                )
            })?;
    Ok(PreparedCarrier320 {
        header_bytes,
        manifest_bytes,
        signature_body_bytes,
        encrypted_chunks,
    })
}

fn read_carrier_parts<'a>(
    cursor: &mut BoundedCursor<'a>,
) -> Result<CarrierParts320<'a>, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    let header_bytes =
        cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "mailbox header")?;
    let manifest_bytes =
        cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "mailbox manifest")?;
    let signature_envelope_bytes = cursor.read_bounded_bytes(
        MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH,
        "mailbox signature envelope",
    )?;
    let encrypted_chunk_count = usize::from(cursor.read_unsigned16("encrypted chunk count")?);
    if encrypted_chunk_count == 0 || encrypted_chunk_count > MAXIMUM_MAILBOX_CHUNK_COUNT {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(
                "encrypted chunk count",
            ),
        );
    }
    let mut encrypted_chunks = Vec::with_capacity(encrypted_chunk_count);
    for _ in 0..encrypted_chunk_count {
        encrypted_chunks.push(cursor.read_bounded_bytes(
            PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MAXIMUM_PLAINTEXT_CHUNK_BYTE_LENGTH + 16,
            "encrypted chunk",
        )?);
    }
    Ok(CarrierParts320 {
        header_bytes,
        manifest_bytes,
        signature_envelope_bytes,
        encrypted_chunks,
    })
}

fn read_expected_geometry(
    cursor: &mut BoundedCursor<'_>,
) -> Result<ExpectedCarrierGeometry320, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    let source_payload_byte_length = cursor.read_unsigned32("source payload byte length")?;
    let total_carrier_byte_length = cursor.read_unsigned32("total carrier byte length")?;
    let header_byte_length = cursor.read_unsigned32("header byte length")?;
    let manifest_byte_length = cursor.read_unsigned32("manifest byte length")?;
    let signature_envelope_byte_length =
        cursor.read_unsigned32("signature-envelope byte length")?;
    let chunk_count = usize::from(cursor.read_unsigned16("geometry chunk count")?);
    if chunk_count == 0 || chunk_count > MAXIMUM_MAILBOX_CHUNK_COUNT {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(
                "geometry chunk count",
            ),
        );
    }
    let mut encrypted_chunk_byte_lengths = Vec::with_capacity(chunk_count);
    for _ in 0..chunk_count {
        encrypted_chunk_byte_lengths.push(cursor.read_unsigned32("encrypted chunk byte length")?);
    }
    Ok(ExpectedCarrierGeometry320 {
        source_payload_byte_length,
        total_carrier_byte_length,
        header_byte_length,
        manifest_byte_length,
        signature_envelope_byte_length,
        encrypted_chunk_byte_lengths,
    })
}

fn verify_carrier(
    verified: &VerifiedSenderContext320,
    stream: StreamContext320,
    descriptor_bytes: &[u8],
    carrier: &CarrierParts320<'_>,
) -> Result<(), PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    require_stream_context(verified, stream)?;
    verify_pseudorandom_zero_sharing_seed_mailbox_sender_carrier_320(
        &verified.root_terminal,
        &verified.roster,
        stream.sender_position,
        stream.recipient_position,
        descriptor_bytes,
        carrier.header_bytes,
        carrier.manifest_bytes,
        carrier.signature_envelope_bytes,
        &carrier.encrypted_chunks,
    )
    .map_err(|error| {
        if matches!(
            error,
            super::pseudorandom_zero_sharing_seed_mailbox_320::PseudorandomZeroSharingSeedMailboxError320::InvalidSenderSignature
        ) {
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::SignatureMismatch
        } else {
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::CarrierMismatch(
                "carrier verification",
            )
        }
    })
}

fn validate_geometry(
    expected: &ExpectedCarrierGeometry320,
    carrier: &CarrierParts320<'_>,
) -> Result<(), PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    let header =
        PseudorandomZeroSharingSeedMailboxHeaderBody320::from_canonical_bytes(carrier.header_bytes)
            .map_err(|_| {
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::CarrierMismatch("header")
            })?;
    let manifest = PseudorandomZeroSharingSeedMailboxManifestBody320::from_canonical_bytes(
        carrier.manifest_bytes,
    )
    .map_err(|_| {
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::CarrierMismatch("manifest")
    })?;
    manifest.require_header(&header).map_err(|_| {
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::CarrierMismatch("manifest header")
    })?;
    let actual_chunk_byte_lengths = header.encrypted_chunk_byte_lengths().map_err(|_| {
        PseudorandomZeroSharingSeedMailboxSenderKernelError320::CarrierMismatch("chunk geometry")
    })?;
    let actual_source_payload_byte_length =
        usize::try_from(header.delivery_descriptor().payload_byte_length()).map_err(|_| {
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(
                "source payload byte length",
            )
        })?;
    let actual_total_carrier_byte_length = carrier
        .header_bytes
        .len()
        .checked_add(carrier.manifest_bytes.len())
        .and_then(|length| length.checked_add(carrier.signature_envelope_bytes.len()))
        .and_then(|length| {
            carrier
                .encrypted_chunks
                .iter()
                .try_fold(length, |sum, chunk| sum.checked_add(chunk.len()))
        })
        .ok_or(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(
                "total carrier byte length",
            ),
        )?;
    let actual_manifest_byte_length =
        pseudorandom_zero_sharing_seed_mailbox_manifest_body_byte_length(header.chunk_count())
            .map_err(|_| {
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::CarrierMismatch(
                    "manifest geometry",
                )
            })?;
    if expected.source_payload_byte_length != actual_source_payload_byte_length
        || expected.total_carrier_byte_length != actual_total_carrier_byte_length
        || expected.header_byte_length
            != PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_BODY_BYTE_LENGTH
        || carrier.header_bytes.len()
            != PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_HEADER_BODY_BYTE_LENGTH
        || expected.manifest_byte_length != actual_manifest_byte_length
        || carrier.manifest_bytes.len() != actual_manifest_byte_length
        || expected.signature_envelope_byte_length
            != PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH
        || carrier.signature_envelope_bytes.len()
            != PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_ENVELOPE_BYTE_LENGTH
        || expected.encrypted_chunk_byte_lengths != actual_chunk_byte_lengths
        || carrier.encrypted_chunks.len() != actual_chunk_byte_lengths.len()
        || carrier
            .encrypted_chunks
            .iter()
            .zip(&actual_chunk_byte_lengths)
            .any(|(chunk, expected_byte_length)| chunk.len() != *expected_byte_length)
    {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::CarrierMismatch(
                "carrier geometry",
            ),
        );
    }
    Ok(())
}

fn append_unsigned16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_unsigned32(
    bytes: &mut Vec<u8>,
    value: usize,
) -> Result<(), PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| {
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(
                    "response byte length",
                )
            })?
            .to_le_bytes(),
    );
    Ok(())
}

fn response_header(status: u8) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend_from_slice(RESPONSE_MAGIC);
    append_unsigned16(&mut bytes, CODEC_VERSION);
    bytes.push(status);
    bytes
}

fn encode_failure_response(
    error: &PseudorandomZeroSharingSeedMailboxSenderKernelError320,
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

fn append_bounded_bytes(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    append_unsigned32(output, value.len())?;
    output.extend_from_slice(value);
    if output.len() > MAXIMUM_COPIED_BUFFER_BYTE_LENGTH {
        return Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(
                "response byte length",
            ),
        );
    }
    Ok(())
}

fn append_encrypted_chunks(
    output: &mut Vec<u8>,
    encrypted_chunks: &[impl AsRef<[u8]>],
) -> Result<(), PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    append_unsigned16(
        output,
        u16::try_from(encrypted_chunks.len()).map_err(|_| {
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(
                "encrypted chunk count",
            )
        })?,
    );
    for encrypted_chunk in encrypted_chunks {
        append_bounded_bytes(output, encrypted_chunk.as_ref())?;
    }
    Ok(())
}

fn encode_prepared_carrier_response(
    prepared: &PreparedCarrier320,
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    let mut bytes = response_header(PREPARED_CARRIER_STATUS);
    append_bounded_bytes(&mut bytes, &prepared.header_bytes)?;
    append_bounded_bytes(&mut bytes, &prepared.manifest_bytes)?;
    append_bounded_bytes(&mut bytes, &prepared.signature_body_bytes)?;
    append_encrypted_chunks(&mut bytes, &prepared.encrypted_chunks)?;
    Ok(bytes)
}

fn encode_carrier_response(
    carrier: &CarrierParts320<'_>,
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    let mut bytes = response_header(COMPLETE_CARRIER_STATUS);
    append_bounded_bytes(&mut bytes, carrier.header_bytes)?;
    append_bounded_bytes(&mut bytes, carrier.manifest_bytes)?;
    append_bounded_bytes(&mut bytes, carrier.signature_envelope_bytes)?;
    append_encrypted_chunks(&mut bytes, &carrier.encrypted_chunks)?;
    Ok(bytes)
}

fn parse_request(
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedMailboxSenderKernelError320> {
    let mut cursor = BoundedCursor::new(bytes)?;
    cursor.require_magic(REQUEST_MAGIC, "request magic")?;
    cursor.require_version("request version")?;
    let operation = cursor.read_unsigned8("operation")?;
    match operation {
        OPEN_CONTEXT_OPERATION => {
            let verified = verify_open_context(parse_open_context_request(&mut cursor)?)?;
            let verification_key = verified.roster.entries[usize::from(verified.sender_position)]
                .signing_verification_key;
            let handle = retain_verified_context(verified)?;
            Ok(encode_open_response(handle, &verification_key))
        }
        PREPARE_CARRIER_OPERATION => {
            let handle =
                u32::try_from(cursor.read_unsigned32("context handle")?).map_err(|_| {
                    PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest(
                        "context handle",
                    )
                })?;
            let stream = read_stream_context(&mut cursor)?;
            let descriptor_bytes = cursor
                .read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "delivery descriptor")?;
            let encapsulation_randomness = cursor.read_exact(32, "encapsulation randomness")?;
            cursor.require_complete("prepare-carrier trailing bytes")?;
            let prepared = with_verified_context(handle, |verified| {
                produce_prepared_carrier(
                    verified,
                    stream,
                    descriptor_bytes,
                    encapsulation_randomness,
                )
            })?;
            encode_prepared_carrier_response(&prepared)
        }
        COMPLETE_CARRIER_OPERATION => {
            let handle =
                u32::try_from(cursor.read_unsigned32("context handle")?).map_err(|_| {
                    PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest(
                        "context handle",
                    )
                })?;
            let stream = read_stream_context(&mut cursor)?;
            let descriptor_bytes = cursor
                .read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "delivery descriptor")?;
            let header_bytes =
                cursor.read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "mailbox header")?;
            let manifest_bytes = cursor
                .read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "mailbox manifest")?;
            let encrypted_chunk_count =
                usize::from(cursor.read_unsigned16("encrypted chunk count")?);
            if encrypted_chunk_count == 0 || encrypted_chunk_count > MAXIMUM_MAILBOX_CHUNK_COUNT {
                return Err(
                    PseudorandomZeroSharingSeedMailboxSenderKernelError320::ResourceLimit(
                        "encrypted chunk count",
                    ),
                );
            }
            let mut encrypted_chunks = Vec::with_capacity(encrypted_chunk_count);
            for _ in 0..encrypted_chunk_count {
                encrypted_chunks.push(cursor.read_bounded_bytes(
                    PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_MAXIMUM_PLAINTEXT_CHUNK_BYTE_LENGTH + 16,
                    "encrypted chunk",
                )?);
            }
            let signature = cursor
                .read_exact(ML_DSA_65_SIGNATURE_BYTE_LENGTH, "sender signature")?
                .try_into()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest(
                        "sender signature",
                    )
                })?;
            cursor.require_complete("complete-carrier trailing bytes")?;
            let header =
                PseudorandomZeroSharingSeedMailboxHeaderBody320::from_canonical_bytes(header_bytes)
                    .map_err(|_| {
                        PseudorandomZeroSharingSeedMailboxSenderKernelError320::CarrierMismatch(
                            "header",
                        )
                    })?;
            let manifest = PseudorandomZeroSharingSeedMailboxManifestBody320::from_canonical_bytes(
                manifest_bytes,
            )
            .map_err(|_| {
                PseudorandomZeroSharingSeedMailboxSenderKernelError320::CarrierMismatch("manifest")
            })?;
            let signature_body =
                PseudorandomZeroSharingSeedMailboxSignatureBody320::new(&header, &manifest)
                    .map_err(|_| {
                        PseudorandomZeroSharingSeedMailboxSenderKernelError320::CarrierMismatch(
                            "signature body",
                        )
                    })?;
            let signature_envelope =
                PseudorandomZeroSharingSignedSeedMailboxManifestEnvelope320::new(
                    signature_body,
                    signature,
                )
                .canonical_bytes()
                .map_err(|_| {
                    PseudorandomZeroSharingSeedMailboxSenderKernelError320::CarrierMismatch(
                        "signature envelope",
                    )
                })?;
            let carrier = CarrierParts320 {
                header_bytes,
                manifest_bytes,
                signature_envelope_bytes: &signature_envelope,
                encrypted_chunks,
            };
            with_verified_context(handle, |verified| {
                verify_carrier(verified, stream, descriptor_bytes, &carrier)
            })?;
            encode_carrier_response(&carrier)
        }
        VALIDATE_CARRIER_OPERATION => {
            let handle =
                u32::try_from(cursor.read_unsigned32("context handle")?).map_err(|_| {
                    PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest(
                        "context handle",
                    )
                })?;
            let stream = read_stream_context(&mut cursor)?;
            let descriptor_bytes = cursor
                .read_bounded_bytes(MAXIMUM_CONTROL_OBJECT_BYTE_LENGTH, "delivery descriptor")?;
            let expected_geometry = read_expected_geometry(&mut cursor)?;
            let carrier = read_carrier_parts(&mut cursor)?;
            cursor.require_complete("validate-carrier trailing bytes")?;
            validate_geometry(&expected_geometry, &carrier)?;
            with_verified_context(handle, |verified| {
                verify_carrier(verified, stream, descriptor_bytes, &carrier)
            })?;
            Ok(response_header(VALIDATION_STATUS))
        }
        CLOSE_CONTEXT_OPERATION => {
            let handle =
                u32::try_from(cursor.read_unsigned32("context handle")?).map_err(|_| {
                    PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest(
                        "context handle",
                    )
                })?;
            cursor.require_complete("close-context trailing bytes")?;
            close_verified_context(handle)?;
            Ok(response_header(CLOSED_CONTEXT_STATUS))
        }
        _ => Err(
            PseudorandomZeroSharingSeedMailboxSenderKernelError320::MalformedRequest("operation"),
        ),
    }
}

pub(crate) fn run_pseudorandom_zero_sharing_seed_mailbox_sender_kernel_320(
    input: &[u8],
) -> Zeroizing<Vec<u8>> {
    match parse_request(input) {
        Ok(response) => response,
        Err(error) => encode_failure_response(&error),
    }
}

#[cfg(test)]
pub(crate) fn clear_pseudorandom_zero_sharing_seed_mailbox_sender_contexts_for_test_320() {
    VERIFIED_SENDER_CONTEXTS.with(|registry| {
        let mut registry = registry.borrow_mut();
        registry.retained = None;
        registry.next_handle = 1;
    });
}

#[cfg(test)]
pub(crate) fn response_signature_body_byte_length_for_test_320() -> usize {
    super::pseudorandom_zero_sharing_seed_mailbox_320::PSEUDORANDOM_ZERO_SHARING_SEED_MAILBOX_SIGNATURE_BODY_BYTE_LENGTH
}
