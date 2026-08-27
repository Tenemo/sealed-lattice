use core::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalTuple,
    Hash512,
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    pseudorandom_zero_sharing_pair_and_coin_seed_320::{
        COLLECTIVE_COIN_SOURCE_BYTE_LENGTH, CommitmentMatchedCollectiveCoinSource320,
        CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH,
        PseudorandomZeroSharingPairSeedScope320, SeedCatalogSecretLeafError320,
        verify_collective_coin_source_opening_catalog_inclusion_320,
        verify_pseudorandom_zero_sharing_pair_seed_opening_catalog_inclusion_320,
    },
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogCoordinate320,
        PseudorandomZeroSharingSeedCatalogLayout320,
        verify_pseudorandom_zero_sharing_subset_seed_opening_catalog_inclusion_320,
    },
    pseudorandom_zero_sharing_seed_catalog_root_terminal_320::{
        PseudorandomZeroSharingSeedCatalogRootTerminalError320,
        RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    },
    pseudorandom_zero_sharing_seed_master_custody_320::VerifiedJoinedSeedMasterCustody320,
    pseudorandom_zero_sharing_seed_receipt_320::{
        PseudorandomZeroSharingSeedReceiptError320,
        RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
    },
    pseudorandom_zero_sharing_seed_receipt_terminal_320::{
        PseudorandomZeroSharingSeedReceiptTerminalError320,
        RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320,
    },
    pseudorandom_zero_sharing_subset_seed_320::{
        CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        PseudorandomZeroSharingSubsetMasterScope320,
    },
};

pub(crate) const PSEUDORANDOM_ZERO_SHARING_JOINED_SEED_MASTER_CUSTODY_DOMAIN: &str =
    "sealed-lattice/tally-preparation/pseudorandom-zero-sharing/joined-seed-master-custody/v1";
const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;

/// One bounded local opening and inclusion path in canonical catalog order.
#[derive(Clone, Copy)]
pub(crate) struct PseudorandomZeroSharingLocalSeedCatalogEntryBytes320<'a> {
    opening_bytes: &'a [u8],
    inclusion_proof_bytes: &'a [u8],
}

impl<'a> PseudorandomZeroSharingLocalSeedCatalogEntryBytes320<'a> {
    pub(crate) const fn new(opening_bytes: &'a [u8], inclusion_proof_bytes: &'a [u8]) -> Self {
        Self {
            opening_bytes,
            inclusion_proof_bytes,
        }
    }
}

impl fmt::Debug for PseudorandomZeroSharingLocalSeedCatalogEntryBytes320<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingLocalSeedCatalogEntryBytes320")
            .field("opening_byte_length", &self.opening_bytes.len())
            .field(
                "inclusion_proof_byte_length",
                &self.inclusion_proof_bytes.len(),
            )
            .field("carrier_bytes", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedMasterJoinError320 {
    RootTerminal(PseudorandomZeroSharingSeedCatalogRootTerminalError320),
    Receipt(PseudorandomZeroSharingSeedReceiptError320),
    ReceiptTerminal(PseudorandomZeroSharingSeedReceiptTerminalError320),
    Preparation {
        phase: &'static str,
        error: TallyPreparationError,
    },
    SecretLeaf {
        phase: &'static str,
        error: SeedCatalogSecretLeafError320,
    },
    LocalCatalogEntryCount {
        expected: usize,
        actual: usize,
    },
    InventoryCount {
        inventory: &'static str,
        expected: usize,
        actual: usize,
    },
    ObjectMismatch {
        field: &'static str,
    },
    ArithmeticOverflow,
    IntegerConversion,
}

impl fmt::Display for PseudorandomZeroSharingSeedMasterJoinError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootTerminal(error) => write!(formatter, "seed root terminal failed: {error}"),
            Self::Receipt(error) => write!(formatter, "retained local receipt failed: {error}"),
            Self::ReceiptTerminal(error) => {
                write!(formatter, "seed receipt terminal failed: {error}")
            }
            Self::Preparation { phase, error } => write!(formatter, "{phase} failed: {error}"),
            Self::SecretLeaf { phase, error } => write!(formatter, "{phase} failed: {error}"),
            Self::LocalCatalogEntryCount { expected, actual } => write!(
                formatter,
                "local seed catalog has {actual} entries; expected {expected}"
            ),
            Self::InventoryCount {
                inventory,
                expected,
                actual,
            } => write!(
                formatter,
                "{inventory} has {actual} entries; expected {expected}"
            ),
            Self::ObjectMismatch { field } => {
                write!(formatter, "seed master join has a wrong {field}")
            }
            Self::ArithmeticOverflow => formatter.write_str("seed master join arithmetic overflow"),
            Self::IntegerConversion => {
                formatter.write_str("seed master join integer conversion failed")
            }
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedMasterJoinError320 {}

/// The participant's complete local catalog after every opening matches the
/// root selected by the all-roster root terminal.
///
/// This type proves catalog correspondence only. It does not prove durable
/// custody, receipt agreement, erasure, or authority to use a seed.
pub(crate) struct RootTerminalMatchedPseudorandomZeroSharingLocalSeedCatalog320 {
    root_terminal_identity: Hash512,
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    subset_contributions: Box<[CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320]>,
    pair_contributions: Box<[CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320]>,
    collective_coin_source: CommitmentMatchedCollectiveCoinSource320,
}

impl fmt::Debug for RootTerminalMatchedPseudorandomZeroSharingLocalSeedCatalog320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootTerminalMatchedPseudorandomZeroSharingLocalSeedCatalog320")
            .field("root_terminal_identity", &self.root_terminal_identity)
            .field("layout", &self.layout)
            .field(
                "subset_contribution_count",
                &self.subset_contributions.len(),
            )
            .field("pair_contribution_count", &self.pair_contributions.len())
            .field("secret_material", &"[redacted]")
            .finish()
    }
}

/// Verifies and completely consumes one local catalog in its canonical order.
pub(crate) fn verify_pseudorandom_zero_sharing_local_seed_catalog_320(
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    participant_position: u16,
    entries: &[PseudorandomZeroSharingLocalSeedCatalogEntryBytes320<'_>],
) -> Result<
    RootTerminalMatchedPseudorandomZeroSharingLocalSeedCatalog320,
    PseudorandomZeroSharingSeedMasterJoinError320,
> {
    let root_body = root_terminal
        .root_inventory()
        .root_body(participant_position)
        .ok_or(
            PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
                field: "local catalog participant position",
            },
        )?;
    let layout = root_body.layout();
    let expected_entry_count = usize::try_from(layout.leaf_count())
        .map_err(|_| PseudorandomZeroSharingSeedMasterJoinError320::IntegerConversion)?;
    if entries.len() != expected_entry_count {
        return Err(
            PseudorandomZeroSharingSeedMasterJoinError320::LocalCatalogEntryCount {
                expected: expected_entry_count,
                actual: entries.len(),
            },
        );
    }

    let root_body_bytes = root_body.canonical_bytes().map_err(|error| {
        PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
            phase: "local seed-catalog root encoding",
            error,
        }
    })?;
    let coordinates = layout.coordinates().map_err(|error| {
        PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
            phase: "local seed-catalog coordinate derivation",
            error,
        }
    })?;
    let mut subset_contributions = Vec::with_capacity(
        usize::try_from(layout.subset_leaf_count())
            .map_err(|_| PseudorandomZeroSharingSeedMasterJoinError320::IntegerConversion)?,
    );
    let mut pair_contributions = Vec::with_capacity(
        usize::try_from(layout.pair_leaf_count())
            .map_err(|_| PseudorandomZeroSharingSeedMasterJoinError320::IntegerConversion)?,
    );
    let mut collective_coin_source = None;

    for (coordinate, entry) in coordinates.zip(entries.iter().copied()) {
        match coordinate {
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(subset) => {
                let (_, contribution) =
                    verify_pseudorandom_zero_sharing_subset_seed_opening_catalog_inclusion_320(
                        layout,
                        subset,
                        &root_body_bytes,
                        entry.opening_bytes,
                        entry.inclusion_proof_bytes,
                    )
                    .map_err(|error| {
                        PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
                            phase: "local subset contribution verification",
                            error,
                        }
                    })?;
                subset_contributions.push(contribution);
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::Pair {
                lower_roster_position,
                upper_roster_position,
            } => {
                let counterpart_position = if participant_position == lower_roster_position {
                    upper_roster_position
                } else {
                    lower_roster_position
                };
                let (_, contribution) =
                    verify_pseudorandom_zero_sharing_pair_seed_opening_catalog_inclusion_320(
                        layout,
                        counterpart_position,
                        &root_body_bytes,
                        entry.opening_bytes,
                        entry.inclusion_proof_bytes,
                    )
                    .map_err(|error| {
                        PseudorandomZeroSharingSeedMasterJoinError320::SecretLeaf {
                            phase: "local pair contribution verification",
                            error,
                        }
                    })?;
                pair_contributions.push(contribution);
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin => {
                if collective_coin_source.is_some() {
                    return Err(
                        PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
                            field: "local collective-coin source count",
                        },
                    );
                }
                let (_, source) = verify_collective_coin_source_opening_catalog_inclusion_320(
                    layout,
                    &root_body_bytes,
                    entry.opening_bytes,
                    entry.inclusion_proof_bytes,
                )
                .map_err(|error| {
                    PseudorandomZeroSharingSeedMasterJoinError320::SecretLeaf {
                        phase: "local collective-coin source verification",
                        error,
                    }
                })?;
                collective_coin_source = Some(source);
            }
        }
    }

    require_count(
        "local subset contribution inventory",
        usize::try_from(layout.subset_leaf_count())
            .map_err(|_| PseudorandomZeroSharingSeedMasterJoinError320::IntegerConversion)?,
        subset_contributions.len(),
    )?;
    require_count(
        "local pair contribution inventory",
        usize::try_from(layout.pair_leaf_count())
            .map_err(|_| PseudorandomZeroSharingSeedMasterJoinError320::IntegerConversion)?,
        pair_contributions.len(),
    )?;
    let collective_coin_source = collective_coin_source.ok_or(
        PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
            field: "local collective-coin source count",
        },
    )?;

    Ok(
        RootTerminalMatchedPseudorandomZeroSharingLocalSeedCatalog320 {
            root_terminal_identity: root_terminal
                .identity()
                .map_err(PseudorandomZeroSharingSeedMasterJoinError320::RootTerminal)?,
            layout,
            subset_contributions: subset_contributions.into_boxed_slice(),
            pair_contributions: pair_contributions.into_boxed_slice(),
            collective_coin_source,
        },
    )
}

/// One joined subset master with no raw constructor.
pub(crate) struct LocallyJoinedPseudorandomZeroSharingSubsetMaster320 {
    scope: PseudorandomZeroSharingSubsetMasterScope320,
    bytes: [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
}

impl LocallyJoinedPseudorandomZeroSharingSubsetMaster320 {
    pub(crate) const fn scope(&self) -> PseudorandomZeroSharingSubsetMasterScope320 {
        self.scope
    }

    pub(crate) const fn as_bytes(
        &self,
    ) -> &[u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH] {
        &self.bytes
    }
}

impl fmt::Debug for LocallyJoinedPseudorandomZeroSharingSubsetMaster320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocallyJoinedPseudorandomZeroSharingSubsetMaster320([redacted])")
    }
}

impl Drop for LocallyJoinedPseudorandomZeroSharingSubsetMaster320 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
pub(super) fn locally_joined_subset_master_for_test(
    scope: PseudorandomZeroSharingSubsetMasterScope320,
    bytes: [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
) -> LocallyJoinedPseudorandomZeroSharingSubsetMaster320 {
    LocallyJoinedPseudorandomZeroSharingSubsetMaster320 { scope, bytes }
}

/// Constructs deterministic diagnostic custody only in the dedicated scalar
/// measurement build. This raw route is absent from the production package.
#[cfg(feature = "preparation-zero-sharing-measurement")]
pub(super) fn locally_joined_subset_master_for_measurement(
    scope: PseudorandomZeroSharingSubsetMasterScope320,
    bytes: [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
) -> LocallyJoinedPseudorandomZeroSharingSubsetMaster320 {
    LocallyJoinedPseudorandomZeroSharingSubsetMaster320 { scope, bytes }
}

/// One joined pair master with no raw constructor.
pub(crate) struct LocallyJoinedPseudorandomZeroSharingPairMaster320 {
    scope: PseudorandomZeroSharingPairSeedScope320,
    bytes: [u8; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
}

impl LocallyJoinedPseudorandomZeroSharingPairMaster320 {
    pub(crate) const fn scope(&self) -> PseudorandomZeroSharingPairSeedScope320 {
        self.scope
    }

    pub(crate) const fn as_bytes(
        &self,
    ) -> &[u8; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH] {
        &self.bytes
    }
}

impl fmt::Debug for LocallyJoinedPseudorandomZeroSharingPairMaster320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocallyJoinedPseudorandomZeroSharingPairMaster320([redacted])")
    }
}

impl Drop for LocallyJoinedPseudorandomZeroSharingPairMaster320 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// The participant's own committed coin source retained unopened.
pub(crate) struct LocallyJoinedCollectiveCoinSource320 {
    bytes: [u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
}

impl LocallyJoinedCollectiveCoinSource320 {
    pub(crate) const fn as_bytes(&self) -> &[u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH] {
        &self.bytes
    }
}

impl fmt::Debug for LocallyJoinedCollectiveCoinSource320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocallyJoinedCollectiveCoinSource320([redacted])")
    }
}

impl Drop for LocallyJoinedCollectiveCoinSource320 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Exact local/global join after the public receipt terminal contains the same
/// signed receipt as the participant's retained authenticated inventory.
///
/// Construction consumes all raw in-memory contribution objects. The result
/// deliberately has no durable-retention, coin-opening, burn, or preparation-
/// continuation authority. A later state owner must durably retain these exact
/// masters and the unopened coin source before deleting persistent raw custody.
pub(crate) struct LocallyJoinedPseudorandomZeroSharingSeedMasters320 {
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    root_terminal_identity: Hash512,
    root_terminal_certificate_identity: Hash512,
    receipt_terminal_identity: Hash512,
    receipt_terminal_certificate_identity: Hash512,
    authenticated_recipient_inventory_identity: Hash512,
    receipt_body_identity: Hash512,
    receipt_envelope_identity: Hash512,
    participant_position: u16,
    subset_masters: Box<[LocallyJoinedPseudorandomZeroSharingSubsetMaster320]>,
    pair_masters: Box<[LocallyJoinedPseudorandomZeroSharingPairMaster320]>,
    collective_coin_source: LocallyJoinedCollectiveCoinSource320,
}

impl LocallyJoinedPseudorandomZeroSharingSeedMasters320 {
    pub(crate) const fn parameter_identity(&self) -> Hash512 {
        self.parameter_identity
    }

    pub(crate) const fn preparation_context(&self) -> TallyPreparationContext {
        self.preparation_context
    }

    pub(crate) const fn root_terminal_identity(&self) -> Hash512 {
        self.root_terminal_identity
    }

    pub(crate) const fn root_terminal_certificate_identity(&self) -> Hash512 {
        self.root_terminal_certificate_identity
    }

    pub(crate) const fn receipt_terminal_identity(&self) -> Hash512 {
        self.receipt_terminal_identity
    }

    pub(crate) const fn receipt_terminal_certificate_identity(&self) -> Hash512 {
        self.receipt_terminal_certificate_identity
    }

    pub(crate) const fn authenticated_recipient_inventory_identity(&self) -> Hash512 {
        self.authenticated_recipient_inventory_identity
    }

    pub(crate) const fn receipt_body_identity(&self) -> Hash512 {
        self.receipt_body_identity
    }

    pub(crate) const fn receipt_envelope_identity(&self) -> Hash512 {
        self.receipt_envelope_identity
    }

    pub(crate) const fn participant_position(&self) -> u16 {
        self.participant_position
    }

    pub(crate) fn subset_masters(&self) -> &[LocallyJoinedPseudorandomZeroSharingSubsetMaster320] {
        &self.subset_masters
    }

    pub(crate) fn pair_masters(&self) -> &[LocallyJoinedPseudorandomZeroSharingPairMaster320] {
        &self.pair_masters
    }

    pub(crate) const fn collective_coin_source(&self) -> &LocallyJoinedCollectiveCoinSource320 {
        &self.collective_coin_source
    }

    pub(crate) fn retained_secret_byte_length(
        &self,
    ) -> Result<usize, PseudorandomZeroSharingSeedMasterJoinError320> {
        self.subset_masters
            .len()
            .checked_mul(PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH)
            .and_then(|length| {
                self.pair_masters
                    .len()
                    .checked_mul(PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH)
                    .and_then(|pair_length| length.checked_add(pair_length))
            })
            .and_then(|length| length.checked_add(COLLECTIVE_COIN_SOURCE_BYTE_LENGTH))
            .ok_or(PseudorandomZeroSharingSeedMasterJoinError320::ArithmeticOverflow)
    }

    /// Encodes the exact joined secrets and their verified semantic provenance
    /// for encrypted local retention.
    ///
    /// The bytes remain inert secret custody. Decoding them is deliberately not
    /// a master constructor and cannot create coin-opening, burn, or preparation-
    /// continuation authority.
    pub(crate) fn custody_payload_bytes(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, PseudorandomZeroSharingSeedMasterJoinError320> {
        let subset_master_count = u16::try_from(self.subset_masters.len())
            .map_err(|_| PseudorandomZeroSharingSeedMasterJoinError320::IntegerConversion)?;
        let pair_master_count = u16::try_from(self.pair_masters.len())
            .map_err(|_| PseudorandomZeroSharingSeedMasterJoinError320::IntegerConversion)?;
        let retained_secret_byte_length = self.retained_secret_byte_length()?;
        let mut retained_secret_bytes =
            Zeroizing::new(Vec::with_capacity(retained_secret_byte_length));
        for master in &self.subset_masters {
            retained_secret_bytes.extend_from_slice(master.as_bytes());
        }
        for master in &self.pair_masters {
            retained_secret_bytes.extend_from_slice(master.as_bytes());
        }
        retained_secret_bytes.extend_from_slice(self.collective_coin_source.as_bytes());

        let tuple = Zeroizing::new(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    PSEUDORANDOM_ZERO_SHARING_JOINED_SEED_MASTER_CUSTODY_DOMAIN,
                )
                .map_err(|error| {
                    PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
                        phase: "joined seed-master custody domain encoding",
                        error: error.into(),
                    }
                })?,
                CanonicalItem::hash512(self.parameter_identity.into_bytes()),
                CanonicalItem::variable_bytes(self.preparation_context.canonical_bytes()).map_err(
                    |error| PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
                        phase: "joined seed-master preparation-context encoding",
                        error: error.into(),
                    },
                )?,
                CanonicalItem::hash512(self.preparation_context.identity().into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::unsigned16(self.preparation_context.participant_count()),
                CanonicalItem::unsigned16(self.participant_position),
                CanonicalItem::hash512(self.root_terminal_identity.into_bytes()),
                CanonicalItem::hash512(self.root_terminal_certificate_identity.into_bytes()),
                CanonicalItem::hash512(self.receipt_terminal_identity.into_bytes()),
                CanonicalItem::hash512(self.receipt_terminal_certificate_identity.into_bytes()),
                CanonicalItem::hash512(
                    self.authenticated_recipient_inventory_identity.into_bytes(),
                ),
                CanonicalItem::hash512(self.receipt_body_identity.into_bytes()),
                CanonicalItem::hash512(self.receipt_envelope_identity.into_bytes()),
                CanonicalItem::unsigned16(subset_master_count),
                CanonicalItem::unsigned16(pair_master_count),
                CanonicalItem::variable_bytes(&*retained_secret_bytes).map_err(|error| {
                    PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
                        phase: "joined seed-master secret payload encoding",
                        error: error.into(),
                    }
                })?,
            ],
        ));
        Ok(Zeroizing::new(tuple.encode().map_err(|error| {
            PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
                phase: "joined seed-master custody tuple encoding",
                error: error.into(),
            }
        })?))
    }
}

impl fmt::Debug for LocallyJoinedPseudorandomZeroSharingSeedMasters320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocallyJoinedPseudorandomZeroSharingSeedMasters320")
            .field("parameter_identity", &self.parameter_identity)
            .field(
                "preparation_context_identity",
                &self.preparation_context.identity(),
            )
            .field("root_terminal_identity", &self.root_terminal_identity)
            .field(
                "root_terminal_certificate_identity",
                &self.root_terminal_certificate_identity,
            )
            .field("receipt_terminal_identity", &self.receipt_terminal_identity)
            .field(
                "receipt_terminal_certificate_identity",
                &self.receipt_terminal_certificate_identity,
            )
            .field("participant_position", &self.participant_position)
            .field("subset_master_count", &self.subset_masters.len())
            .field("pair_master_count", &self.pair_masters.len())
            .field("secret_material", &"[redacted]")
            .finish()
    }
}

/// Reconstructs the existing typed master inventory from a capability minted
/// only by the positive joined-custody verifier.
///
/// All fallible layout and scope work completes while the complete moved
/// secret inventory remains inside one zeroizing owner. Each fixed-size master
/// is copied only after those checks pass and is immediately placed in its
/// zeroizing typed owner.
pub(super) fn restore_pseudorandom_zero_sharing_seed_masters_from_verified_custody_320(
    verified_custody: VerifiedJoinedSeedMasterCustody320,
) -> Result<
    LocallyJoinedPseudorandomZeroSharingSeedMasters320,
    PseudorandomZeroSharingSeedMasterJoinError320,
> {
    let parameter_identity = verified_custody.parameter_identity();
    let preparation_context = verified_custody.preparation_context();
    let participant_position = verified_custody.participant_position();
    let root_terminal_identity = verified_custody.root_terminal_identity();
    let root_terminal_certificate_identity = verified_custody.root_terminal_certificate_identity();
    let receipt_terminal_identity = verified_custody.receipt_terminal_identity();
    let receipt_terminal_certificate_identity =
        verified_custody.receipt_terminal_certificate_identity();
    let authenticated_recipient_inventory_identity =
        verified_custody.authenticated_recipient_inventory_identity();
    let receipt_body_identity = verified_custody.receipt_body_identity();
    let receipt_envelope_identity = verified_custody.receipt_envelope_identity();
    let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        parameter_identity,
        preparation_context,
        participant_position,
    )
    .map_err(
        |error| PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
            phase: "restored seed-master catalog layout",
            error,
        },
    )?;
    let expected_subsets = layout
        .coordinates()
        .map_err(
            |error| PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
                phase: "restored subset coordinate derivation",
                error,
            },
        )?
        .filter_map(|coordinate| match coordinate {
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(subset) => Some(subset),
            _ => None,
        })
        .collect::<Vec<_>>();
    let subset_scopes = expected_subsets
        .into_iter()
        .map(|subset| {
            PseudorandomZeroSharingSubsetMasterScope320::new(
                parameter_identity,
                preparation_context,
                subset,
            )
            .map_err(|error| {
                PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
                    phase: "restored subset master scope",
                    error,
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let pair_scopes = (0..layout.participant_count())
        .filter(|counterpart_position| *counterpart_position != participant_position)
        .map(|counterpart_position| {
            super::pseudorandom_zero_sharing_pair_and_coin_seed_320::PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
                layout,
                counterpart_position,
            )
            .map(|coordinate| coordinate.scope())
            .map_err(|error| PseudorandomZeroSharingSeedMasterJoinError320::SecretLeaf {
                phase: "restored pair master scope",
                error,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expected_secret_byte_length = subset_scopes
        .len()
        .checked_mul(PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH)
        .and_then(|byte_length| {
            pair_scopes
                .len()
                .checked_mul(PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH)
                .and_then(|pair_byte_length| byte_length.checked_add(pair_byte_length))
        })
        .and_then(|byte_length| byte_length.checked_add(COLLECTIVE_COIN_SOURCE_BYTE_LENGTH))
        .ok_or(PseudorandomZeroSharingSeedMasterJoinError320::ArithmeticOverflow)?;
    let retained_secret_bytes = verified_custody.into_retained_secret_bytes();
    require_count(
        "restored joined secret bytes",
        expected_secret_byte_length,
        retained_secret_bytes.len(),
    )?;

    let mut byte_offset = 0_usize;
    let mut subset_masters = Vec::with_capacity(subset_scopes.len());
    for scope in subset_scopes {
        let byte_end = byte_offset + PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH;
        let mut master_bytes =
            Zeroizing::new([0_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH]);
        master_bytes.copy_from_slice(&retained_secret_bytes[byte_offset..byte_end]);
        subset_masters.push(LocallyJoinedPseudorandomZeroSharingSubsetMaster320 {
            scope,
            bytes: *master_bytes,
        });
        byte_offset = byte_end;
    }
    let mut pair_masters = Vec::with_capacity(pair_scopes.len());
    for scope in pair_scopes {
        let byte_end = byte_offset + PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH;
        let mut master_bytes =
            Zeroizing::new([0_u8; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH]);
        master_bytes.copy_from_slice(&retained_secret_bytes[byte_offset..byte_end]);
        pair_masters.push(LocallyJoinedPseudorandomZeroSharingPairMaster320 {
            scope,
            bytes: *master_bytes,
        });
        byte_offset = byte_end;
    }
    let coin_byte_end = byte_offset + COLLECTIVE_COIN_SOURCE_BYTE_LENGTH;
    let mut collective_coin_source_bytes =
        Zeroizing::new([0_u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH]);
    collective_coin_source_bytes
        .copy_from_slice(&retained_secret_bytes[byte_offset..coin_byte_end]);
    debug_assert_eq!(coin_byte_end, retained_secret_bytes.len());

    Ok(LocallyJoinedPseudorandomZeroSharingSeedMasters320 {
        parameter_identity,
        preparation_context,
        root_terminal_identity,
        root_terminal_certificate_identity,
        receipt_terminal_identity,
        receipt_terminal_certificate_identity,
        authenticated_recipient_inventory_identity,
        receipt_body_identity,
        receipt_envelope_identity,
        participant_position,
        subset_masters: subset_masters.into_boxed_slice(),
        pair_masters: pair_masters.into_boxed_slice(),
        collective_coin_source: LocallyJoinedCollectiveCoinSource320 {
            bytes: *collective_coin_source_bytes,
        },
    })
}

/// Consumes the participant's exact local and remote authenticated seed
/// custody only after its retained receipt matches the all-roster terminal.
pub(crate) fn join_pseudorandom_zero_sharing_seed_masters_320(
    local_catalog: RootTerminalMatchedPseudorandomZeroSharingLocalSeedCatalog320,
    retained_local_receipt: RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
    receipt_terminal: RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320,
) -> Result<
    LocallyJoinedPseudorandomZeroSharingSeedMasters320,
    PseudorandomZeroSharingSeedMasterJoinError320,
> {
    let receipt_terminal_root_identity = receipt_terminal
        .root_terminal()
        .identity()
        .map_err(PseudorandomZeroSharingSeedMasterJoinError320::RootTerminal)?;
    require_match(
        local_catalog.root_terminal_identity == receipt_terminal_root_identity,
        "local catalog root-terminal identity",
    )?;
    let retained_receipt_body = retained_local_receipt.receipt_body();
    let participant_position = retained_receipt_body.recipient_position();
    require_match(
        local_catalog.layout.contributor_position() == participant_position,
        "local catalog participant position",
    )?;
    require_match(
        retained_receipt_body.root_terminal_identity() == receipt_terminal_root_identity,
        "retained receipt root-terminal identity",
    )?;
    let public_receipt = receipt_terminal
        .receipt_inventory()
        .receipts()
        .get(usize::from(participant_position))
        .ok_or(
            PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
                field: "public receipt participant position",
            },
        )?;
    require_match(
        public_receipt.receipt_body() == retained_receipt_body,
        "retained receipt body",
    )?;
    require_match(
        public_receipt.receipt_envelope_identity()
            == retained_local_receipt.receipt_envelope_identity(),
        "retained receipt envelope identity",
    )?;

    let receipt_terminal_identity = receipt_terminal
        .identity()
        .map_err(PseudorandomZeroSharingSeedMasterJoinError320::ReceiptTerminal)?;
    let root_terminal_certificate_identity =
        receipt_terminal.root_terminal().certificate_identity();
    let receipt_terminal_certificate_identity = receipt_terminal.certificate_identity();
    let expected_catalog_identities = (0..local_catalog.layout.participant_count())
        .map(|contributor_position| {
            receipt_terminal
                .root_terminal()
                .root_inventory()
                .root_body(contributor_position)
                .map(|root_body| root_body.layout().identity())
                .ok_or(
                    PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
                        field: "root-terminal contributor catalog identity",
                    },
                )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let authenticated_recipient_inventory_identity = retained_local_receipt
        .recipient_inventory()
        .body()
        .identity()
        .map_err(PseudorandomZeroSharingSeedMasterJoinError320::Receipt)?;
    let receipt_body_identity = retained_receipt_body
        .identity()
        .map_err(PseudorandomZeroSharingSeedMasterJoinError320::Receipt)?;
    let receipt_envelope_identity = retained_local_receipt.receipt_envelope_identity();

    let remote_deliveries = retained_local_receipt
        .into_recipient_inventory()
        .into_root_matched_inventory()
        .into_deliveries();
    let mut subset_contributions = Vec::new();
    let mut pair_contributions = Vec::new();
    for delivery in remote_deliveries {
        let (delivery_subset_entries, pair_contribution) = delivery.into_contributions();
        subset_contributions.extend(
            delivery_subset_entries
                .into_vec()
                .into_iter()
                .map(|entry| entry.into_contribution()),
        );
        pair_contributions.push(pair_contribution);
    }
    subset_contributions.extend(local_catalog.subset_contributions.into_vec());
    pair_contributions.extend(local_catalog.pair_contributions.into_vec());

    subset_contributions.sort_unstable_by_key(|contribution| {
        let coordinate = contribution.coordinate();
        (
            coordinate.master_scope().subset().excluded_position_mask(),
            coordinate.contributor_position(),
        )
    });
    pair_contributions.sort_unstable_by_key(|contribution| {
        let coordinate = contribution.coordinate();
        (
            coordinate.scope().lower_roster_position(),
            coordinate.scope().upper_roster_position(),
            coordinate.contributor_position(),
        )
    });

    let expected_subsets = local_catalog
        .layout
        .coordinates()
        .map_err(
            |error| PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
                phase: "joined subset coordinate derivation",
                error,
            },
        )?
        .filter_map(|coordinate| match coordinate {
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(subset) => Some(subset),
            _ => None,
        })
        .collect::<Vec<_>>();
    let expected_subset_contribution_count =
        expected_subsets.iter().try_fold(0_usize, |count, subset| {
            count
                .checked_add(subset.member_positions().len())
                .ok_or(PseudorandomZeroSharingSeedMasterJoinError320::ArithmeticOverflow)
        })?;
    require_count(
        "joined subset contribution inventory",
        expected_subset_contribution_count,
        subset_contributions.len(),
    )?;
    let mut subset_contribution_iterator = subset_contributions.into_iter();
    let mut subset_masters = Vec::with_capacity(expected_subsets.len());
    for subset in expected_subsets {
        let expected_scope = PseudorandomZeroSharingSubsetMasterScope320::new(
            local_catalog.layout.parameter_identity(),
            local_catalog.layout.preparation_context(),
            subset,
        )
        .map_err(
            |error| PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
                phase: "joined subset master scope derivation",
                error,
            },
        )?;
        let member_positions = subset.member_positions();
        let contributions = (0..member_positions.len())
            .map(|_| {
                subset_contribution_iterator.next().ok_or(
                    PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
                        field: "joined subset contribution exhaustion",
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        subset_masters.push(combine_subset_master(
            expected_scope,
            &expected_catalog_identities,
            contributions,
        )?);
    }
    require_match(
        subset_contribution_iterator.next().is_none(),
        "joined subset contribution remainder",
    )?;

    let expected_pair_count = usize::try_from(local_catalog.layout.pair_leaf_count())
        .map_err(|_| PseudorandomZeroSharingSeedMasterJoinError320::IntegerConversion)?;
    let expected_pair_contribution_count = expected_pair_count
        .checked_mul(2)
        .ok_or(PseudorandomZeroSharingSeedMasterJoinError320::ArithmeticOverflow)?;
    require_count(
        "joined pair contribution inventory",
        expected_pair_contribution_count,
        pair_contributions.len(),
    )?;
    let mut pair_contribution_iterator = pair_contributions.into_iter();
    let mut pair_masters = Vec::with_capacity(expected_pair_count);
    for counterpart_position in (0..local_catalog.layout.participant_count())
        .filter(|position| *position != participant_position)
    {
        let expected_coordinate = super::pseudorandom_zero_sharing_pair_and_coin_seed_320::PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
            local_catalog.layout,
            counterpart_position,
        )
        .map_err(|error| PseudorandomZeroSharingSeedMasterJoinError320::SecretLeaf {
            phase: "joined pair master scope derivation",
            error,
        })?;
        let contributions = (0..2)
            .map(|_| {
                pair_contribution_iterator.next().ok_or(
                    PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
                        field: "joined pair contribution exhaustion",
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        pair_masters.push(combine_pair_master(
            expected_coordinate.scope(),
            &expected_catalog_identities,
            contributions,
        )?);
    }
    require_match(
        pair_contribution_iterator.next().is_none(),
        "joined pair contribution remainder",
    )?;

    let (_, collective_coin_source_bytes) = local_catalog.collective_coin_source.into_parts();
    let collective_coin_source_bytes = Zeroizing::new(collective_coin_source_bytes);
    Ok(LocallyJoinedPseudorandomZeroSharingSeedMasters320 {
        parameter_identity: local_catalog.layout.parameter_identity(),
        preparation_context: local_catalog.layout.preparation_context(),
        root_terminal_identity: receipt_terminal_root_identity,
        root_terminal_certificate_identity,
        receipt_terminal_identity,
        receipt_terminal_certificate_identity,
        authenticated_recipient_inventory_identity,
        receipt_body_identity,
        receipt_envelope_identity,
        participant_position,
        subset_masters: subset_masters.into_boxed_slice(),
        pair_masters: pair_masters.into_boxed_slice(),
        collective_coin_source: LocallyJoinedCollectiveCoinSource320 {
            bytes: *collective_coin_source_bytes,
        },
    })
}

fn combine_subset_master(
    expected_scope: PseudorandomZeroSharingSubsetMasterScope320,
    expected_catalog_identities: &[Hash512],
    contributions: Vec<CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320>,
) -> Result<
    LocallyJoinedPseudorandomZeroSharingSubsetMaster320,
    PseudorandomZeroSharingSeedMasterJoinError320,
> {
    let expected_contributors = expected_scope.subset().member_positions();
    require_count(
        "one subset contribution inventory",
        expected_contributors.len(),
        contributions.len(),
    )?;
    let mut master =
        Zeroizing::new([0_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH]);
    for (contribution_index, (contribution, expected_contributor_position)) in contributions
        .into_iter()
        .zip(expected_contributors)
        .enumerate()
    {
        let (coordinate, contribution_bytes) = contribution.into_parts();
        let contribution_bytes = Zeroizing::new(contribution_bytes);
        require_match(
            coordinate.master_scope() == expected_scope,
            "subset contribution master scope",
        )?;
        if coordinate.contributor_position() != expected_contributor_position {
            return Err(
                PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
                    phase: "subset contribution order",
                    error: TallyPreparationError::PseudorandomZeroSharingSubsetSeedContributorOrderMismatch {
                        contribution_index,
                        expected_contributor_position,
                        actual_contributor_position: coordinate.contributor_position(),
                    },
                },
            );
        }
        let expected_catalog_identity = expected_catalog_identities
            .get(usize::from(expected_contributor_position))
            .ok_or(
                PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
                    field: "subset contribution catalog position",
                },
            )?;
        require_match(
            coordinate.seed_catalog_identity() == *expected_catalog_identity,
            "subset contribution catalog identity",
        )?;
        for (master_byte, contribution_byte) in master.iter_mut().zip(contribution_bytes.iter()) {
            *master_byte ^= contribution_byte;
        }
    }
    Ok(LocallyJoinedPseudorandomZeroSharingSubsetMaster320 {
        scope: expected_scope,
        bytes: *master,
    })
}

fn combine_pair_master(
    expected_scope: PseudorandomZeroSharingPairSeedScope320,
    expected_catalog_identities: &[Hash512],
    contributions: Vec<CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320>,
) -> Result<
    LocallyJoinedPseudorandomZeroSharingPairMaster320,
    PseudorandomZeroSharingSeedMasterJoinError320,
> {
    let expected_contributors = [
        expected_scope.lower_roster_position(),
        expected_scope.upper_roster_position(),
    ];
    require_count(
        "one pair contribution inventory",
        expected_contributors.len(),
        contributions.len(),
    )?;
    let mut master =
        Zeroizing::new([0_u8; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH]);
    for (contribution_index, (contribution, expected_contributor_position)) in contributions
        .into_iter()
        .zip(expected_contributors)
        .enumerate()
    {
        let (coordinate, contribution_bytes) = contribution.into_parts();
        let contribution_bytes = Zeroizing::new(contribution_bytes);
        require_match(
            coordinate.scope() == expected_scope,
            "pair contribution master scope",
        )?;
        if coordinate.contributor_position() != expected_contributor_position {
            return Err(PseudorandomZeroSharingSeedMasterJoinError320::SecretLeaf {
                phase: "pair contribution order",
                error: SeedCatalogSecretLeafError320::PairContributorOrderMismatch {
                    contribution_index,
                    expected_contributor_position,
                    actual_contributor_position: coordinate.contributor_position(),
                },
            });
        }
        let expected_catalog_identity = expected_catalog_identities
            .get(usize::from(expected_contributor_position))
            .ok_or(
                PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
                    field: "pair contribution catalog position",
                },
            )?;
        require_match(
            coordinate.seed_catalog_identity() == *expected_catalog_identity,
            "pair contribution catalog identity",
        )?;
        for (master_byte, contribution_byte) in master.iter_mut().zip(contribution_bytes.iter()) {
            *master_byte ^= contribution_byte;
        }
    }
    Ok(LocallyJoinedPseudorandomZeroSharingPairMaster320 {
        scope: expected_scope,
        bytes: *master,
    })
}

#[cfg(test)]
pub(super) fn combine_subset_master_for_test(
    expected_scope: PseudorandomZeroSharingSubsetMasterScope320,
    expected_catalog_identities: &[Hash512],
    contributions: Vec<CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320>,
) -> Result<
    LocallyJoinedPseudorandomZeroSharingSubsetMaster320,
    PseudorandomZeroSharingSeedMasterJoinError320,
> {
    combine_subset_master(expected_scope, expected_catalog_identities, contributions)
}

#[cfg(test)]
pub(super) fn combine_pair_master_for_test(
    expected_scope: PseudorandomZeroSharingPairSeedScope320,
    expected_catalog_identities: &[Hash512],
    contributions: Vec<CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320>,
) -> Result<
    LocallyJoinedPseudorandomZeroSharingPairMaster320,
    PseudorandomZeroSharingSeedMasterJoinError320,
> {
    combine_pair_master(expected_scope, expected_catalog_identities, contributions)
}

fn require_count(
    inventory: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), PseudorandomZeroSharingSeedMasterJoinError320> {
    if expected != actual {
        return Err(
            PseudorandomZeroSharingSeedMasterJoinError320::InventoryCount {
                inventory,
                expected,
                actual,
            },
        );
    }
    Ok(())
}

fn require_match(
    condition: bool,
    field: &'static str,
) -> Result<(), PseudorandomZeroSharingSeedMasterJoinError320> {
    if !condition {
        return Err(PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch { field });
    }
    Ok(())
}
