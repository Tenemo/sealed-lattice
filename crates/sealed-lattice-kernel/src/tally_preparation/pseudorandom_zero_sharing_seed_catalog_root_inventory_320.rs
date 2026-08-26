use core::fmt;

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError, CanonicalItem,
    CanonicalTuple, Hash512, Roster, hash_foundation_tuple_512,
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogLayout320, PseudorandomZeroSharingSeedCatalogRootBody320,
    },
    pseudorandom_zero_sharing_seed_catalog_state_output_320::{
        PseudorandomZeroSharingSeedCatalogStateOutputError,
        StateAndRosterAuthorizedPseudorandomZeroSharingSeedCatalogRoot320,
        verify_state_and_roster_authorized_pseudorandom_zero_sharing_seed_catalog_root_320,
    },
};

const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const ROOT_INVENTORY_PREFIX_ITEM_COUNT: usize = 5;

pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_INVENTORY_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-root-inventory";
pub(crate) const PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_INVENTORY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/seed-catalog-root-inventory-identity";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PseudorandomZeroSharingSeedCatalogRootInventoryError {
    Canonical(CanonicalCodecError),
    Preparation(TallyPreparationError),
    RootAuthorization {
        contributor_position: u16,
        error: PseudorandomZeroSharingSeedCatalogStateOutputError,
    },
    PackageCount {
        expected: usize,
        actual: usize,
    },
    IntegerConversion,
}

impl From<CanonicalCodecError> for PseudorandomZeroSharingSeedCatalogRootInventoryError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<TallyPreparationError> for PseudorandomZeroSharingSeedCatalogRootInventoryError {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl fmt::Display for PseudorandomZeroSharingSeedCatalogRootInventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => {
                write!(
                    formatter,
                    "canonical seed-catalog root-inventory error: {error}"
                )
            }
            Self::Preparation(error) => {
                write!(
                    formatter,
                    "seed-catalog root-inventory preparation error: {error}"
                )
            }
            Self::RootAuthorization {
                contributor_position,
                error,
            } => write!(
                formatter,
                "seed-catalog root {contributor_position} is not authorized: {error}"
            ),
            Self::PackageCount { expected, actual } => write!(
                formatter,
                "seed-catalog root inventory has {actual} packages; expected {expected}"
            ),
            Self::IntegerConversion => formatter.write_str(
                "seed-catalog root-inventory position does not fit its canonical integer",
            ),
        }
    }
}

impl std::error::Error for PseudorandomZeroSharingSeedCatalogRootInventoryError {}

/// Borrowed untrusted carriers for one contributor's root authorization chain.
#[derive(Clone, Copy)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320<'a> {
    root_body_bytes: &'a [u8],
    reservation_certificate_bytes: &'a [u8],
    exact_output_certificate_bytes: &'a [u8],
    contributor_signature_envelope_bytes: &'a [u8],
}

impl<'a> PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320<'a> {
    pub(crate) const fn new(
        root_body_bytes: &'a [u8],
        reservation_certificate_bytes: &'a [u8],
        exact_output_certificate_bytes: &'a [u8],
        contributor_signature_envelope_bytes: &'a [u8],
    ) -> Self {
        Self {
            root_body_bytes,
            reservation_certificate_bytes,
            exact_output_certificate_bytes,
            contributor_signature_envelope_bytes,
        }
    }
}

impl fmt::Debug for PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320")
            .field("root_body_byte_length", &self.root_body_bytes.len())
            .field(
                "reservation_certificate_byte_length",
                &self.reservation_certificate_bytes.len(),
            )
            .field(
                "exact_output_certificate_byte_length",
                &self.exact_output_certificate_bytes.len(),
            )
            .field(
                "contributor_signature_envelope_byte_length",
                &self.contributor_signature_envelope_bytes.len(),
            )
            .field("carrier_bytes", &"[redacted]")
            .finish()
    }
}

/// Certificate-free semantic body for the complete roster-ordered root set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PseudorandomZeroSharingSeedCatalogRootInventoryBody320 {
    parameter_identity: Hash512,
    preparation_context_identity: Hash512,
    participant_count: u16,
    root_body_identities: Box<[Hash512]>,
}

impl PseudorandomZeroSharingSeedCatalogRootInventoryBody320 {
    fn new(
        parameter_identity: Hash512,
        preparation_context: TallyPreparationContext,
        authorized_roots: &[StateAndRosterAuthorizedPseudorandomZeroSharingSeedCatalogRoot320],
    ) -> Result<Self, PseudorandomZeroSharingSeedCatalogRootInventoryError> {
        let expected_root_count = usize::from(preparation_context.participant_count());
        if authorized_roots.len() != expected_root_count {
            return Err(
                PseudorandomZeroSharingSeedCatalogRootInventoryError::PackageCount {
                    expected: expected_root_count,
                    actual: authorized_roots.len(),
                },
            );
        }
        let root_body_identities = authorized_roots
            .iter()
            .map(|authorized_root| {
                authorized_root
                    .root_body()
                    .identity()
                    .map_err(PseudorandomZeroSharingSeedCatalogRootInventoryError::from)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();
        Ok(Self {
            parameter_identity,
            preparation_context_identity: preparation_context.identity(),
            participant_count: preparation_context.participant_count(),
            root_body_identities,
        })
    }

    pub(crate) const fn parameter_identity(&self) -> Hash512 {
        self.parameter_identity
    }

    pub(crate) const fn preparation_context_identity(&self) -> Hash512 {
        self.preparation_context_identity
    }

    pub(crate) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(crate) fn root_body_identities(&self) -> &[Hash512] {
        &self.root_body_identities
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, PseudorandomZeroSharingSeedCatalogRootInventoryError> {
        let mut items =
            Vec::with_capacity(ROOT_INVENTORY_PREFIX_ITEM_COUNT + self.root_body_identities.len());
        items.push(CanonicalItem::nonempty_ascii(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_INVENTORY_BODY_DOMAIN,
        )?);
        items.push(CanonicalItem::hash512(self.parameter_identity.into_bytes()));
        items.push(CanonicalItem::hash512(
            self.preparation_context_identity.into_bytes(),
        ));
        items.push(CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL));
        items.push(CanonicalItem::unsigned16(self.participant_count));
        items.extend(
            self.root_body_identities
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
    ) -> Result<Hash512, PseudorandomZeroSharingSeedCatalogRootInventoryError> {
        Ok(hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_INVENTORY_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

/// Complete semantic root inventory after every individual byte chain passes.
///
/// Durable vote production and local rollback reconciliation remain separate
/// implementation requirements. This type is not a private-delivery or global
/// preparation capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320 {
    body: PseudorandomZeroSharingSeedCatalogRootInventoryBody320,
    authorized_roots: Box<[StateAndRosterAuthorizedPseudorandomZeroSharingSeedCatalogRoot320]>,
}

impl VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320 {
    pub(crate) const fn body(&self) -> &PseudorandomZeroSharingSeedCatalogRootInventoryBody320 {
        &self.body
    }

    pub(crate) fn authorized_roots(
        &self,
    ) -> &[StateAndRosterAuthorizedPseudorandomZeroSharingSeedCatalogRoot320] {
        &self.authorized_roots
    }

    pub(crate) fn root_body(
        &self,
        contributor_position: u16,
    ) -> Option<PseudorandomZeroSharingSeedCatalogRootBody320> {
        self.authorized_roots
            .get(usize::from(contributor_position))
            .map(|authorized_root| authorized_root.root_body())
    }

    pub(crate) fn identity(
        &self,
    ) -> Result<Hash512, PseudorandomZeroSharingSeedCatalogRootInventoryError> {
        self.body.identity()
    }
}

pub(crate) fn verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    roster: &Roster,
    packages: &[PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320<'_>],
) -> Result<
    VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
    PseudorandomZeroSharingSeedCatalogRootInventoryError,
> {
    let expected_package_count = usize::from(preparation_context.participant_count());
    if packages.len() != expected_package_count {
        return Err(
            PseudorandomZeroSharingSeedCatalogRootInventoryError::PackageCount {
                expected: expected_package_count,
                actual: packages.len(),
            },
        );
    }
    let mut authorized_roots = Vec::with_capacity(expected_package_count);
    for (contributor_index, package) in packages.iter().enumerate() {
        let contributor_position = u16::try_from(contributor_index)
            .map_err(|_| PseudorandomZeroSharingSeedCatalogRootInventoryError::IntegerConversion)?;
        let expected_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
            parameter_identity,
            preparation_context,
            contributor_position,
        )?;
        let authorized_root =
            verify_state_and_roster_authorized_pseudorandom_zero_sharing_seed_catalog_root_320(
                expected_layout,
                package.root_body_bytes,
                roster,
                package.reservation_certificate_bytes,
                package.exact_output_certificate_bytes,
                package.contributor_signature_envelope_bytes,
            )
            .map_err(|error| {
                PseudorandomZeroSharingSeedCatalogRootInventoryError::RootAuthorization {
                    contributor_position,
                    error,
                }
            })?;
        authorized_roots.push(authorized_root);
    }
    let body = PseudorandomZeroSharingSeedCatalogRootInventoryBody320::new(
        parameter_identity,
        preparation_context,
        &authorized_roots,
    )?;
    Ok(VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320 {
        body,
        authorized_roots: authorized_roots.into_boxed_slice(),
    })
}
