use core::fmt;

use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512, Roster,
    derive_foundation_roster_parameters, hash_foundation_tuple_512,
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    binary_field_320::BinaryFieldElement320,
    collective_coin_source_bivariate_sharing_320::{
        CollectiveCoinSourceBivariateCrosspoint320, CollectiveCoinSourceBivariateRow320,
        CollectiveCoinSourceBivariateSharingError320, CollectiveCoinSourceComponent320,
        CollectiveCoinSourceSymmetricBivariatePolynomial320,
    },
    pseudorandom_zero_sharing_320::canonical_evaluation_point_320,
    pseudorandom_zero_sharing_seed_master_join_320::LocallyJoinedPseudorandomZeroSharingSeedMasters320,
};

const COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_LAYOUT_VERSION: u16 = 1;
const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const SECRET_AXIS_COORDINATE_KIND_CODE: u8 = 1;
const CROSSPOINT_COORDINATE_KIND_CODE: u8 = 2;
const ROOT_BODY_PREFIX_ITEM_COUNT: usize = 16;
const SIGNATURE_ENVELOPE_ITEM_COUNT: usize = 3;
const PRIVATE_ROW_BODY_ITEM_COUNT: usize = 8;
const MAXIMUM_ROOT_BODY_BYTE_LENGTH: usize = 128 * 1024;
const MAXIMUM_ROOT_BODY_ITEM_COUNT: usize = 768;
const MAXIMUM_ROOT_BODY_ITEM_BYTE_LENGTH: usize = 8 * 1024;
const MAXIMUM_ROOT_BODY_CUMULATIVE_BYTE_LENGTH: usize = 512 * 1024;
const MAXIMUM_SIGNATURE_ENVELOPE_BYTE_LENGTH: usize = 8 * 1024;
const MAXIMUM_SIGNATURE_ENVELOPE_ITEM_BYTE_LENGTH: usize = 4 * 1024;
const MAXIMUM_PRIVATE_ROW_BODY_BYTE_LENGTH: usize = 16 * 1024;
const MAXIMUM_PRIVATE_ROW_BODY_ITEM_BYTE_LENGTH: usize = 8 * 1024;
const CANONICAL_TUPLE_HEADER_BYTE_LENGTH: usize = 8;
const CANONICAL_ITEM_HEADER_BYTE_LENGTH: usize = 6;
const CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH: usize = 4;

pub(crate) const COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH: usize = 64;
pub(crate) const COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_LAYOUT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/collective-coin/bivariate-commitment-layout-identity";
pub(crate) const COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_DIGEST_DOMAIN: &str =
    "sealed-lattice/v1/preparation/collective-coin/bivariate-commitment-digest";
pub(crate) const COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_ROOT_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/collective-coin/bivariate-commitment-root-body";
pub(crate) const COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_ROOT_BODY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/collective-coin/bivariate-commitment-root-body-identity";
pub(crate) const COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/preparation/collective-coin/bivariate-commitment-root";
pub(crate) const COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SIGNATURE_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/preparation/collective-coin/bivariate-commitment-signature-envelope";
pub(crate) const COLLECTIVE_COIN_SOURCE_BIVARIATE_PRIVATE_ROW_BODY_DOMAIN: &str =
    "sealed-lattice/v1/preparation/collective-coin/bivariate-private-row-body";
pub(crate) const COLLECTIVE_COIN_SOURCE_BIVARIATE_ML_DSA_65_SIGNATURE_BYTE_LENGTH: usize = 3_309;

pub(crate) fn collective_coin_source_bivariate_private_row_body_byte_length(
    participant_count: u16,
) -> Result<usize, CollectiveCoinSourceBivariateCommitmentError320> {
    derive_foundation_roster_parameters(participant_count).ok_or(
        CollectiveCoinSourceBivariateCommitmentError320::UnsupportedRoster { participant_count },
    )?;
    let payload_byte_length = private_row_payload_byte_length(participant_count)?;
    CANONICAL_TUPLE_HEADER_BYTE_LENGTH
        .checked_add(
            PRIVATE_ROW_BODY_ITEM_COUNT
                .checked_mul(CANONICAL_ITEM_HEADER_BYTE_LENGTH)
                .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)?,
        )
        .and_then(|length| length.checked_add(CANONICAL_VARIABLE_VALUE_LENGTH_PREFIX_BYTE_LENGTH))
        .and_then(|length| {
            length.checked_add(COLLECTIVE_COIN_SOURCE_BIVARIATE_PRIVATE_ROW_BODY_DOMAIN.len())
        })
        .and_then(|length| length.checked_add(2 * Hash512::BYTE_LENGTH))
        .and_then(|length| length.checked_add(4 * size_of::<u16>()))
        .and_then(|length| length.checked_add(payload_byte_length))
        .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CollectiveCoinSourceBivariateCommitmentError320 {
    Canonical(CanonicalCodecError),
    Preparation(TallyPreparationError),
    Sharing(CollectiveCoinSourceBivariateSharingError320),
    UnsupportedRoster {
        participant_count: u16,
    },
    ContributorPositionOutOfRange {
        contributor_position: u16,
        participant_count: u16,
    },
    HolderPositionOutOfRange {
        holder_position: u16,
        participant_count: u16,
    },
    PolynomialScopeMismatch,
    SaltCountMismatch {
        expected: usize,
        actual: usize,
    },
    CommitmentDigestCountMismatch {
        expected: usize,
        actual: usize,
    },
    ObjectMismatch {
        field: &'static str,
    },
    PrivateRowPayloadByteLength {
        expected: usize,
        actual: usize,
    },
    CommitmentMismatch {
        leaf_ordinal: u64,
    },
    LocalRowDegreeMismatch {
        holder_position: u16,
        component: CollectiveCoinSourceComponent320,
    },
    RosterMismatch,
    SignatureByteLength {
        expected: usize,
        actual: usize,
    },
    MalformedSigningVerificationKey,
    InvalidSignature,
    ArithmeticOverflow,
    IntegerConversion,
}

impl From<CanonicalCodecError> for CollectiveCoinSourceBivariateCommitmentError320 {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<TallyPreparationError> for CollectiveCoinSourceBivariateCommitmentError320 {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl From<CollectiveCoinSourceBivariateSharingError320>
    for CollectiveCoinSourceBivariateCommitmentError320
{
    fn from(error: CollectiveCoinSourceBivariateSharingError320) -> Self {
        Self::Sharing(error)
    }
}

impl fmt::Display for CollectiveCoinSourceBivariateCommitmentError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => write!(
                formatter,
                "canonical collective-coin bivariate commitment error: {error}"
            ),
            Self::Preparation(error) => {
                write!(
                    formatter,
                    "collective-coin commitment preparation error: {error}"
                )
            }
            Self::Sharing(error) => {
                write!(
                    formatter,
                    "collective-coin commitment sharing error: {error}"
                )
            }
            Self::UnsupportedRoster { participant_count } => write!(
                formatter,
                "participant count {participant_count} does not admit collective-coin bivariate commitments"
            ),
            Self::ContributorPositionOutOfRange {
                contributor_position,
                participant_count,
            } => write!(
                formatter,
                "collective-coin contributor position {contributor_position} is outside participant count {participant_count}"
            ),
            Self::HolderPositionOutOfRange {
                holder_position,
                participant_count,
            } => write!(
                formatter,
                "collective-coin holder position {holder_position} is outside participant count {participant_count}"
            ),
            Self::PolynomialScopeMismatch => formatter
                .write_str("collective-coin polynomial does not match the commitment layout scope"),
            Self::SaltCountMismatch { expected, actual } => write!(
                formatter,
                "collective-coin commitment source has {actual} salts; expected {expected}"
            ),
            Self::CommitmentDigestCountMismatch { expected, actual } => write!(
                formatter,
                "collective-coin commitment root has {actual} digests; expected {expected}"
            ),
            Self::ObjectMismatch { field } => {
                write!(
                    formatter,
                    "collective-coin commitment object has a wrong {field}"
                )
            }
            Self::PrivateRowPayloadByteLength { expected, actual } => write!(
                formatter,
                "collective-coin private row payload has {actual} bytes; expected {expected}"
            ),
            Self::CommitmentMismatch { leaf_ordinal } => write!(
                formatter,
                "collective-coin private row opening does not match commitment leaf {leaf_ordinal}"
            ),
            Self::LocalRowDegreeMismatch {
                holder_position,
                component,
            } => write!(
                formatter,
                "collective-coin private row for holder {holder_position} is not locally degree bounded in the {component} component"
            ),
            Self::RosterMismatch => formatter.write_str(
                "collective-coin commitment roster does not match the preparation context",
            ),
            Self::SignatureByteLength { expected, actual } => write!(
                formatter,
                "collective-coin root signature has {actual} bytes; expected {expected}"
            ),
            Self::MalformedSigningVerificationKey => formatter.write_str(
                "collective-coin contributor has a malformed ML-DSA-65 verification key",
            ),
            Self::InvalidSignature => {
                formatter.write_str("collective-coin commitment root has an invalid signature")
            }
            Self::ArithmeticOverflow => {
                formatter.write_str("collective-coin commitment arithmetic overflow")
            }
            Self::IntegerConversion => {
                formatter.write_str("collective-coin commitment integer conversion failed")
            }
        }
    }
}

impl std::error::Error for CollectiveCoinSourceBivariateCommitmentError320 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::Preparation(error) => Some(error),
            Self::Sharing(error) => Some(error),
            Self::UnsupportedRoster { .. }
            | Self::ContributorPositionOutOfRange { .. }
            | Self::HolderPositionOutOfRange { .. }
            | Self::PolynomialScopeMismatch
            | Self::SaltCountMismatch { .. }
            | Self::CommitmentDigestCountMismatch { .. }
            | Self::ObjectMismatch { .. }
            | Self::PrivateRowPayloadByteLength { .. }
            | Self::CommitmentMismatch { .. }
            | Self::LocalRowDegreeMismatch { .. }
            | Self::RosterMismatch
            | Self::SignatureByteLength { .. }
            | Self::MalformedSigningVerificationKey
            | Self::InvalidSignature
            | Self::ArithmeticOverflow
            | Self::IntegerConversion => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum CollectiveCoinSourceBivariateCommitmentCoordinate320 {
    SecretAxis {
        component: CollectiveCoinSourceComponent320,
        holder_position: u16,
    },
    Crosspoint {
        component: CollectiveCoinSourceComponent320,
        lower_holder_position: u16,
        upper_holder_position: u16,
    },
}

impl CollectiveCoinSourceBivariateCommitmentCoordinate320 {
    const fn component(self) -> CollectiveCoinSourceComponent320 {
        match self {
            Self::SecretAxis { component, .. } | Self::Crosspoint { component, .. } => component,
        }
    }

    const fn kind_code(self) -> u8 {
        match self {
            Self::SecretAxis { .. } => SECRET_AXIS_COORDINATE_KIND_CODE,
            Self::Crosspoint { .. } => CROSSPOINT_COORDINATE_KIND_CODE,
        }
    }

    fn append_hash_items(self, items: &mut Vec<CanonicalItem>) {
        items.push(CanonicalItem::unsigned8(
            u8::try_from(self.component().position() + 1)
                .expect("three component positions fit in u8"),
        ));
        items.push(CanonicalItem::unsigned8(self.kind_code()));
        match self {
            Self::SecretAxis {
                holder_position, ..
            } => items.push(CanonicalItem::unsigned16(holder_position)),
            Self::Crosspoint {
                lower_holder_position,
                upper_holder_position,
                ..
            } => {
                items.push(CanonicalItem::unsigned16(lower_holder_position));
                items.push(CanonicalItem::unsigned16(upper_holder_position));
            }
        }
    }
}

/// Value-independent scope for one contributor's three flat commitment
/// inventories. The seed root and receipt terminal identities bind the exact
/// joined predecessor from which the source and salt are consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CollectiveCoinSourceBivariateCommitmentLayout320 {
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    seed_root_terminal_identity: Hash512,
    seed_receipt_terminal_identity: Hash512,
    contributor_position: u16,
    reconstruction_threshold: u16,
    secret_axis_leaf_count_per_component: u64,
    crosspoint_leaf_count_per_component: u64,
    leaf_count_per_component: u64,
    leaf_count: u64,
    identity: Hash512,
}

impl CollectiveCoinSourceBivariateCommitmentLayout320 {
    pub(crate) fn from_joined_seed_masters(
        joined_seed_masters: &LocallyJoinedPseudorandomZeroSharingSeedMasters320,
    ) -> Result<Self, CollectiveCoinSourceBivariateCommitmentError320> {
        Self::derive(
            joined_seed_masters.parameter_identity(),
            joined_seed_masters.preparation_context(),
            joined_seed_masters.root_terminal_identity(),
            joined_seed_masters.receipt_terminal_identity(),
            joined_seed_masters.participant_position(),
        )
    }

    pub(crate) fn derive(
        parameter_identity: Hash512,
        preparation_context: TallyPreparationContext,
        seed_root_terminal_identity: Hash512,
        seed_receipt_terminal_identity: Hash512,
        contributor_position: u16,
    ) -> Result<Self, CollectiveCoinSourceBivariateCommitmentError320> {
        let participant_count = preparation_context.participant_count();
        let roster_parameters = derive_foundation_roster_parameters(participant_count).ok_or(
            CollectiveCoinSourceBivariateCommitmentError320::UnsupportedRoster {
                participant_count,
            },
        )?;
        if contributor_position >= participant_count {
            return Err(
                CollectiveCoinSourceBivariateCommitmentError320::ContributorPositionOutOfRange {
                    contributor_position,
                    participant_count,
                },
            );
        }
        let secret_axis_leaf_count_per_component = u64::from(participant_count);
        let crosspoint_leaf_count_per_component = secret_axis_leaf_count_per_component
            .checked_mul(
                secret_axis_leaf_count_per_component
                    .checked_sub(1)
                    .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)?,
            )
            .and_then(|ordered_pair_count| ordered_pair_count.checked_div(2))
            .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)?;
        let leaf_count_per_component = secret_axis_leaf_count_per_component
            .checked_add(crosspoint_leaf_count_per_component)
            .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)?;
        let leaf_count = leaf_count_per_component
            .checked_mul(
                u64::try_from(CollectiveCoinSourceComponent320::ALL.len()).map_err(|_| {
                    CollectiveCoinSourceBivariateCommitmentError320::IntegerConversion
                })?,
            )
            .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)?;
        let reconstruction_threshold = roster_parameters.reconstruction_threshold;
        let identity = hash_foundation_tuple_512(
            COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_LAYOUT_IDENTITY_DOMAIN,
            &[
                CanonicalItem::unsigned16(
                    COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_LAYOUT_VERSION,
                ),
                CanonicalItem::hash512(parameter_identity.into_bytes()),
                CanonicalItem::hash512(preparation_context.identity().into_bytes()),
                CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
                CanonicalItem::hash512(seed_root_terminal_identity.into_bytes()),
                CanonicalItem::hash512(seed_receipt_terminal_identity.into_bytes()),
                CanonicalItem::unsigned16(participant_count),
                CanonicalItem::unsigned16(contributor_position),
                CanonicalItem::unsigned16(reconstruction_threshold),
                CanonicalItem::unsigned16(
                    u16::try_from(CollectiveCoinSourceComponent320::ALL.len()).map_err(|_| {
                        CollectiveCoinSourceBivariateCommitmentError320::IntegerConversion
                    })?,
                ),
                CanonicalItem::unsigned64(secret_axis_leaf_count_per_component),
                CanonicalItem::unsigned64(crosspoint_leaf_count_per_component),
                CanonicalItem::unsigned64(leaf_count_per_component),
                CanonicalItem::unsigned64(leaf_count),
            ],
        )?;
        Ok(Self {
            parameter_identity,
            preparation_context,
            seed_root_terminal_identity,
            seed_receipt_terminal_identity,
            contributor_position,
            reconstruction_threshold,
            secret_axis_leaf_count_per_component,
            crosspoint_leaf_count_per_component,
            leaf_count_per_component,
            leaf_count,
            identity,
        })
    }

    pub(crate) const fn parameter_identity(self) -> Hash512 {
        self.parameter_identity
    }

    pub(crate) const fn preparation_context(self) -> TallyPreparationContext {
        self.preparation_context
    }

    pub(crate) const fn seed_root_terminal_identity(self) -> Hash512 {
        self.seed_root_terminal_identity
    }

    pub(crate) const fn seed_receipt_terminal_identity(self) -> Hash512 {
        self.seed_receipt_terminal_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.preparation_context.participant_count()
    }

    pub(crate) const fn contributor_position(self) -> u16 {
        self.contributor_position
    }

    pub(crate) const fn reconstruction_threshold(self) -> u16 {
        self.reconstruction_threshold
    }

    pub(crate) const fn secret_axis_leaf_count_per_component(self) -> u64 {
        self.secret_axis_leaf_count_per_component
    }

    pub(crate) const fn crosspoint_leaf_count_per_component(self) -> u64 {
        self.crosspoint_leaf_count_per_component
    }

    pub(crate) const fn leaf_count_per_component(self) -> u64 {
        self.leaf_count_per_component
    }

    pub(crate) const fn leaf_count(self) -> u64 {
        self.leaf_count
    }

    pub(crate) const fn identity(self) -> Hash512 {
        self.identity
    }

    pub(crate) fn coordinates(
        self,
    ) -> Result<
        Vec<CollectiveCoinSourceBivariateCommitmentCoordinate320>,
        CollectiveCoinSourceBivariateCommitmentError320,
    > {
        let mut coordinates = Vec::with_capacity(
            usize::try_from(self.leaf_count)
                .map_err(|_| CollectiveCoinSourceBivariateCommitmentError320::IntegerConversion)?,
        );
        for component in CollectiveCoinSourceComponent320::ALL {
            for holder_position in 0..self.participant_count() {
                coordinates.push(
                    CollectiveCoinSourceBivariateCommitmentCoordinate320::SecretAxis {
                        component,
                        holder_position,
                    },
                );
            }
            for lower_holder_position in 0..self.participant_count() {
                for upper_holder_position in lower_holder_position + 1..self.participant_count() {
                    coordinates.push(
                        CollectiveCoinSourceBivariateCommitmentCoordinate320::Crosspoint {
                            component,
                            lower_holder_position,
                            upper_holder_position,
                        },
                    );
                }
            }
        }
        debug_assert_eq!(coordinates.len(), usize::try_from(self.leaf_count).unwrap());
        Ok(coordinates)
    }

    pub(crate) fn holder_coordinates(
        self,
        holder_position: u16,
    ) -> Result<
        Vec<CollectiveCoinSourceBivariateCommitmentCoordinate320>,
        CollectiveCoinSourceBivariateCommitmentError320,
    > {
        self.validate_holder_position(holder_position)?;
        let mut coordinates = Vec::with_capacity(
            usize::from(self.participant_count())
                .checked_mul(CollectiveCoinSourceComponent320::ALL.len())
                .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)?,
        );
        for component in CollectiveCoinSourceComponent320::ALL {
            coordinates.push(
                CollectiveCoinSourceBivariateCommitmentCoordinate320::SecretAxis {
                    component,
                    holder_position,
                },
            );
            for peer_holder_position in 0..self.participant_count() {
                if peer_holder_position == holder_position {
                    continue;
                }
                coordinates.push(
                    CollectiveCoinSourceBivariateCommitmentCoordinate320::Crosspoint {
                        component,
                        lower_holder_position: holder_position.min(peer_holder_position),
                        upper_holder_position: holder_position.max(peer_holder_position),
                    },
                );
            }
        }
        Ok(coordinates)
    }

    pub(crate) fn leaf_ordinal(
        self,
        coordinate: CollectiveCoinSourceBivariateCommitmentCoordinate320,
    ) -> Result<u64, CollectiveCoinSourceBivariateCommitmentError320> {
        self.validate_coordinate(coordinate)?;
        let component_offset = u64::try_from(coordinate.component().position())
            .map_err(|_| CollectiveCoinSourceBivariateCommitmentError320::IntegerConversion)?
            .checked_mul(self.leaf_count_per_component)
            .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)?;
        let within_component_ordinal = match coordinate {
            CollectiveCoinSourceBivariateCommitmentCoordinate320::SecretAxis {
                holder_position,
                ..
            } => u64::from(holder_position),
            CollectiveCoinSourceBivariateCommitmentCoordinate320::Crosspoint {
                lower_holder_position,
                upper_holder_position,
                ..
            } => self
                .secret_axis_leaf_count_per_component
                .checked_add(pair_ordinal(
                    self.participant_count(),
                    lower_holder_position,
                    upper_holder_position,
                )?)
                .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)?,
        };
        component_offset
            .checked_add(within_component_ordinal)
            .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)
    }

    fn validate_holder_position(
        self,
        holder_position: u16,
    ) -> Result<(), CollectiveCoinSourceBivariateCommitmentError320> {
        if holder_position >= self.participant_count() {
            return Err(
                CollectiveCoinSourceBivariateCommitmentError320::HolderPositionOutOfRange {
                    holder_position,
                    participant_count: self.participant_count(),
                },
            );
        }
        Ok(())
    }

    fn validate_coordinate(
        self,
        coordinate: CollectiveCoinSourceBivariateCommitmentCoordinate320,
    ) -> Result<(), CollectiveCoinSourceBivariateCommitmentError320> {
        match coordinate {
            CollectiveCoinSourceBivariateCommitmentCoordinate320::SecretAxis {
                holder_position,
                ..
            } => self.validate_holder_position(holder_position),
            CollectiveCoinSourceBivariateCommitmentCoordinate320::Crosspoint {
                lower_holder_position,
                upper_holder_position,
                ..
            } => {
                self.validate_holder_position(lower_holder_position)?;
                self.validate_holder_position(upper_holder_position)?;
                if lower_holder_position >= upper_holder_position {
                    return Err(collective_coin_commitment_object_mismatch(
                        "crosspoint holder order",
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct CollectiveCoinSourceBivariateCommitmentOpening320 {
    coordinate: CollectiveCoinSourceBivariateCommitmentCoordinate320,
    value: BinaryFieldElement320,
    salt: [u8; COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH],
}

impl CollectiveCoinSourceBivariateCommitmentOpening320 {
    fn digest(
        &self,
        layout: CollectiveCoinSourceBivariateCommitmentLayout320,
    ) -> Result<Hash512, CollectiveCoinSourceBivariateCommitmentError320> {
        derive_collective_coin_source_bivariate_commitment_digest_320(
            layout,
            self.coordinate,
            self.value,
            self.salt,
        )
    }
}

impl fmt::Debug for CollectiveCoinSourceBivariateCommitmentOpening320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectiveCoinSourceBivariateCommitmentOpening320")
            .field("coordinate", &self.coordinate)
            .field("value", &"[redacted]")
            .field("salt", &"[redacted]")
            .finish()
    }
}

impl Drop for CollectiveCoinSourceBivariateCommitmentOpening320 {
    fn drop(&mut self) {
        self.value.zeroize();
        self.salt.zeroize();
    }
}

/// Public flat digest inventory authenticated by the source contributor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CollectiveCoinSourceBivariateCommitmentRootBody320 {
    layout: CollectiveCoinSourceBivariateCommitmentLayout320,
    commitment_digests: Box<[Hash512]>,
}

impl CollectiveCoinSourceBivariateCommitmentRootBody320 {
    pub(crate) fn new(
        layout: CollectiveCoinSourceBivariateCommitmentLayout320,
        commitment_digests: Vec<Hash512>,
    ) -> Result<Self, CollectiveCoinSourceBivariateCommitmentError320> {
        let expected = usize::try_from(layout.leaf_count())
            .map_err(|_| CollectiveCoinSourceBivariateCommitmentError320::IntegerConversion)?;
        if commitment_digests.len() != expected {
            return Err(
                CollectiveCoinSourceBivariateCommitmentError320::CommitmentDigestCountMismatch {
                    expected,
                    actual: commitment_digests.len(),
                },
            );
        }
        Ok(Self {
            layout,
            commitment_digests: commitment_digests.into_boxed_slice(),
        })
    }

    pub(crate) const fn layout(&self) -> CollectiveCoinSourceBivariateCommitmentLayout320 {
        self.layout
    }

    pub(crate) fn commitment_digests(&self) -> &[Hash512] {
        &self.commitment_digests
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, CollectiveCoinSourceBivariateCommitmentError320> {
        let mut items =
            Vec::with_capacity(ROOT_BODY_PREFIX_ITEM_COUNT + self.commitment_digests.len());
        items.extend([
            CanonicalItem::nonempty_ascii(
                COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_ROOT_BODY_DOMAIN,
            )?,
            CanonicalItem::hash512(self.layout.parameter_identity().into_bytes()),
            CanonicalItem::hash512(self.layout.preparation_context().identity().into_bytes()),
            CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
            CanonicalItem::hash512(self.layout.seed_root_terminal_identity().into_bytes()),
            CanonicalItem::hash512(self.layout.seed_receipt_terminal_identity().into_bytes()),
            CanonicalItem::unsigned16(COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_LAYOUT_VERSION),
            CanonicalItem::hash512(self.layout.identity().into_bytes()),
            CanonicalItem::unsigned16(self.layout.participant_count()),
            CanonicalItem::unsigned16(self.layout.contributor_position()),
            CanonicalItem::unsigned16(self.layout.reconstruction_threshold()),
            CanonicalItem::unsigned16(
                u16::try_from(CollectiveCoinSourceComponent320::ALL.len()).map_err(|_| {
                    CollectiveCoinSourceBivariateCommitmentError320::IntegerConversion
                })?,
            ),
            CanonicalItem::unsigned64(self.layout.secret_axis_leaf_count_per_component()),
            CanonicalItem::unsigned64(self.layout.crosspoint_leaf_count_per_component()),
            CanonicalItem::unsigned64(self.layout.leaf_count_per_component()),
            CanonicalItem::unsigned64(self.layout.leaf_count()),
        ]);
        items.extend(
            self.commitment_digests
                .iter()
                .map(|digest| CanonicalItem::hash512(digest.into_bytes())),
        );
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            items,
        )
        .encode()?)
    }

    pub(crate) fn from_canonical_bytes(
        expected_layout: CollectiveCoinSourceBivariateCommitmentLayout320,
        bytes: &[u8],
    ) -> Result<Self, CollectiveCoinSourceBivariateCommitmentError320> {
        let tuple = CanonicalTuple::decode(bytes, &root_body_decode_limits())?;
        let expected_item_count =
            ROOT_BODY_PREFIX_ITEM_COUNT
                .checked_add(usize::try_from(expected_layout.leaf_count()).map_err(|_| {
                    CollectiveCoinSourceBivariateCommitmentError320::IntegerConversion
                })?)
                .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)?;
        require_object_header(
            &tuple,
            COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_ROOT_BODY_DOMAIN,
            expected_item_count,
        )?;
        require_hash(
            &tuple.items[1],
            expected_layout.parameter_identity(),
            "parameter identity",
        )?;
        require_hash(
            &tuple.items[2],
            expected_layout.preparation_context().identity(),
            "preparation-context identity",
        )?;
        require_u16(
            &tuple.items[3],
            PREPARATION_ATTEMPT_ORDINAL,
            "preparation attempt ordinal",
        )?;
        require_hash(
            &tuple.items[4],
            expected_layout.seed_root_terminal_identity(),
            "seed root-terminal identity",
        )?;
        require_hash(
            &tuple.items[5],
            expected_layout.seed_receipt_terminal_identity(),
            "seed receipt-terminal identity",
        )?;
        require_u16(
            &tuple.items[6],
            COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_LAYOUT_VERSION,
            "layout version",
        )?;
        require_hash(
            &tuple.items[7],
            expected_layout.identity(),
            "layout identity",
        )?;
        require_u16(
            &tuple.items[8],
            expected_layout.participant_count(),
            "participant count",
        )?;
        require_u16(
            &tuple.items[9],
            expected_layout.contributor_position(),
            "contributor position",
        )?;
        require_u16(
            &tuple.items[10],
            expected_layout.reconstruction_threshold(),
            "reconstruction threshold",
        )?;
        require_u16(
            &tuple.items[11],
            u16::try_from(CollectiveCoinSourceComponent320::ALL.len())
                .map_err(|_| CollectiveCoinSourceBivariateCommitmentError320::IntegerConversion)?,
            "component count",
        )?;
        require_u64(
            &tuple.items[12],
            expected_layout.secret_axis_leaf_count_per_component(),
            "secret-axis leaf count per component",
        )?;
        require_u64(
            &tuple.items[13],
            expected_layout.crosspoint_leaf_count_per_component(),
            "crosspoint leaf count per component",
        )?;
        require_u64(
            &tuple.items[14],
            expected_layout.leaf_count_per_component(),
            "leaf count per component",
        )?;
        require_u64(&tuple.items[15], expected_layout.leaf_count(), "leaf count")?;
        let commitment_digests = tuple.items[ROOT_BODY_PREFIX_ITEM_COUNT..]
            .iter()
            .map(|item| read_hash(item, "commitment digest"))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(expected_layout, commitment_digests)
    }

    pub(crate) fn identity(
        &self,
    ) -> Result<Hash512, CollectiveCoinSourceBivariateCommitmentError320> {
        Ok(hash_foundation_tuple_512(
            COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_ROOT_BODY_IDENTITY_DOMAIN,
            &[CanonicalItem::fixed_bytes(self.canonical_bytes()?)?],
        )?)
    }
}

/// Retained producer source for one exact root and every private row opening.
pub(crate) struct CollectiveCoinSourceBivariateCommitmentInventory320 {
    root_body: CollectiveCoinSourceBivariateCommitmentRootBody320,
    openings: Box<[CollectiveCoinSourceBivariateCommitmentOpening320]>,
}

impl CollectiveCoinSourceBivariateCommitmentInventory320 {
    pub(crate) fn create(
        layout: CollectiveCoinSourceBivariateCommitmentLayout320,
        polynomial: &CollectiveCoinSourceSymmetricBivariatePolynomial320,
        commitment_salts: Vec<[u8; COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH]>,
    ) -> Result<Self, CollectiveCoinSourceBivariateCommitmentError320> {
        let mut commitment_salts = Zeroizing::new(commitment_salts);
        if polynomial.participant_count() != layout.participant_count()
            || polynomial.contributor_position() != layout.contributor_position()
        {
            return Err(CollectiveCoinSourceBivariateCommitmentError320::PolynomialScopeMismatch);
        }
        let expected = usize::try_from(layout.leaf_count())
            .map_err(|_| CollectiveCoinSourceBivariateCommitmentError320::IntegerConversion)?;
        if commitment_salts.len() != expected {
            return Err(
                CollectiveCoinSourceBivariateCommitmentError320::SaltCountMismatch {
                    expected,
                    actual: commitment_salts.len(),
                },
            );
        }
        let coordinates = layout.coordinates()?;
        let mut openings = Vec::with_capacity(expected);
        let mut commitment_digests = Vec::with_capacity(expected);
        for ((coordinate, salt), expected_leaf_ordinal) in coordinates
            .into_iter()
            .zip(commitment_salts.iter_mut())
            .zip(0_u64..)
        {
            if layout.leaf_ordinal(coordinate)? != expected_leaf_ordinal {
                return Err(collective_coin_commitment_object_mismatch(
                    "coordinate order",
                ));
            }
            let value = evaluate_commitment_coordinate(layout, polynomial, coordinate)?;
            let salt = core::mem::replace(
                salt,
                [0_u8; COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH],
            );
            let opening = CollectiveCoinSourceBivariateCommitmentOpening320 {
                coordinate,
                value,
                salt,
            };
            commitment_digests.push(opening.digest(layout)?);
            openings.push(opening);
        }
        Ok(Self {
            root_body: CollectiveCoinSourceBivariateCommitmentRootBody320::new(
                layout,
                commitment_digests,
            )?,
            openings: openings.into_boxed_slice(),
        })
    }

    pub(crate) const fn root_body(&self) -> &CollectiveCoinSourceBivariateCommitmentRootBody320 {
        &self.root_body
    }

    pub(crate) fn private_row_body(
        &self,
        holder_position: u16,
    ) -> Result<
        CollectiveCoinSourceBivariatePrivateRowBody320,
        CollectiveCoinSourceBivariateCommitmentError320,
    > {
        let layout = self.root_body.layout();
        let coordinates = layout.holder_coordinates(holder_position)?;
        let mut row_openings = Vec::with_capacity(coordinates.len());
        for coordinate in coordinates {
            let leaf_ordinal = layout.leaf_ordinal(coordinate)?;
            let opening = self
                .openings
                .get(usize::try_from(leaf_ordinal).map_err(|_| {
                    CollectiveCoinSourceBivariateCommitmentError320::IntegerConversion
                })?)
                .ok_or(collective_coin_commitment_object_mismatch(
                    "retained opening",
                ))?;
            if opening.coordinate != coordinate {
                return Err(collective_coin_commitment_object_mismatch(
                    "retained opening coordinate",
                ));
            }
            row_openings.push(opening.clone());
        }
        Ok(CollectiveCoinSourceBivariatePrivateRowBody320 {
            layout,
            root_body_identity: self.root_body.identity()?,
            holder_position,
            openings: row_openings,
        })
    }
}

impl fmt::Debug for CollectiveCoinSourceBivariateCommitmentInventory320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectiveCoinSourceBivariateCommitmentInventory320")
            .field("root_body", &self.root_body)
            .field("openings", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CollectiveCoinSourceBivariateCommitmentSignatureEnvelope320 {
    root_body_identity: Hash512,
    signature: [u8; COLLECTIVE_COIN_SOURCE_BIVARIATE_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl CollectiveCoinSourceBivariateCommitmentSignatureEnvelope320 {
    pub(crate) const fn new(
        root_body_identity: Hash512,
        signature: [u8; COLLECTIVE_COIN_SOURCE_BIVARIATE_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self {
            root_body_identity,
            signature,
        }
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, CollectiveCoinSourceBivariateCommitmentError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SIGNATURE_ENVELOPE_DOMAIN,
                )?,
                CanonicalItem::hash512(self.root_body_identity.into_bytes()),
                CanonicalItem::fixed_bytes(self.signature)?,
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        expected_root_body_identity: Hash512,
        bytes: &[u8],
    ) -> Result<Self, CollectiveCoinSourceBivariateCommitmentError320> {
        let tuple = CanonicalTuple::decode(bytes, &signature_envelope_decode_limits())?;
        require_object_header(
            &tuple,
            COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SIGNATURE_ENVELOPE_DOMAIN,
            SIGNATURE_ENVELOPE_ITEM_COUNT,
        )?;
        require_hash(
            &tuple.items[1],
            expected_root_body_identity,
            "root-body identity",
        )?;
        if tuple.items[2].item_type() != CanonicalItemType::RawBytes {
            return Err(collective_coin_commitment_object_mismatch("signature"));
        }
        let signature =
            <[u8; COLLECTIVE_COIN_SOURCE_BIVARIATE_ML_DSA_65_SIGNATURE_BYTE_LENGTH]>::try_from(
                tuple.items[2].canonical_bytes(),
            )
            .map_err(|_| {
                CollectiveCoinSourceBivariateCommitmentError320::SignatureByteLength {
                    expected: COLLECTIVE_COIN_SOURCE_BIVARIATE_ML_DSA_65_SIGNATURE_BYTE_LENGTH,
                    actual: tuple.items[2].canonical_bytes().len(),
                }
            })?;
        Ok(Self {
            root_body_identity: expected_root_body_identity,
            signature,
        })
    }
}

impl fmt::Debug for CollectiveCoinSourceBivariateCommitmentSignatureEnvelope320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectiveCoinSourceBivariateCommitmentSignatureEnvelope320")
            .field("root_body_identity", &self.root_body_identity)
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorAuthenticatedCollectiveCoinSourceBivariateCommitmentRoot320 {
    root_body: CollectiveCoinSourceBivariateCommitmentRootBody320,
    root_body_identity: Hash512,
}

impl AuthorAuthenticatedCollectiveCoinSourceBivariateCommitmentRoot320 {
    pub(crate) const fn root_body(&self) -> &CollectiveCoinSourceBivariateCommitmentRootBody320 {
        &self.root_body
    }

    pub(crate) const fn root_body_identity(&self) -> Hash512 {
        self.root_body_identity
    }
}

pub(crate) fn verify_collective_coin_source_bivariate_commitment_root_signature_320(
    expected_layout: CollectiveCoinSourceBivariateCommitmentLayout320,
    root_body_bytes: &[u8],
    roster: &Roster,
    signature_envelope_bytes: &[u8],
) -> Result<
    AuthorAuthenticatedCollectiveCoinSourceBivariateCommitmentRoot320,
    CollectiveCoinSourceBivariateCommitmentError320,
> {
    let root_body = CollectiveCoinSourceBivariateCommitmentRootBody320::from_canonical_bytes(
        expected_layout,
        root_body_bytes,
    )?;
    roster
        .validate()
        .map_err(|_| CollectiveCoinSourceBivariateCommitmentError320::RosterMismatch)?;
    if roster.entries.len() != usize::from(expected_layout.participant_count())
        || roster
            .roster_hash()
            .map_err(|_| CollectiveCoinSourceBivariateCommitmentError320::RosterMismatch)?
            != expected_layout.preparation_context().roster_hash()
    {
        return Err(CollectiveCoinSourceBivariateCommitmentError320::RosterMismatch);
    }
    let root_body_identity = root_body.identity()?;
    let signature_envelope =
        CollectiveCoinSourceBivariateCommitmentSignatureEnvelope320::from_canonical_bytes(
            root_body_identity,
            signature_envelope_bytes,
        )?;
    let contributor_position = expected_layout.contributor_position();
    let contributor_roster_entry = roster
        .entries
        .get(usize::from(contributor_position))
        .ok_or(CollectiveCoinSourceBivariateCommitmentError320::RosterMismatch)?;
    if contributor_roster_entry.roster_position != contributor_position {
        return Err(CollectiveCoinSourceBivariateCommitmentError320::RosterMismatch);
    }
    let verification_key =
        ml_dsa_65::PublicKey::try_from_bytes(contributor_roster_entry.signing_verification_key)
            .map_err(|_| {
                CollectiveCoinSourceBivariateCommitmentError320::MalformedSigningVerificationKey
            })?;
    if !verification_key.verify(
        root_body_bytes,
        &signature_envelope.signature,
        COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SIGNATURE_CONTEXT,
    ) {
        return Err(CollectiveCoinSourceBivariateCommitmentError320::InvalidSignature);
    }
    Ok(
        AuthorAuthenticatedCollectiveCoinSourceBivariateCommitmentRoot320 {
            root_body,
            root_body_identity,
        },
    )
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CollectiveCoinSourceBivariatePrivateRowBody320 {
    layout: CollectiveCoinSourceBivariateCommitmentLayout320,
    root_body_identity: Hash512,
    holder_position: u16,
    openings: Vec<CollectiveCoinSourceBivariateCommitmentOpening320>,
}

impl CollectiveCoinSourceBivariatePrivateRowBody320 {
    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, CollectiveCoinSourceBivariateCommitmentError320> {
        let mut payload = Zeroizing::new(Vec::with_capacity(private_row_payload_byte_length(
            self.layout.participant_count(),
        )?));
        for opening in &self.openings {
            payload.extend_from_slice(&opening.value.canonical_bytes());
            payload.extend_from_slice(&opening.salt);
        }
        Ok(Zeroizing::new(
            CanonicalTuple::new(
                CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
                CANONICAL_TUPLE_VERSION,
                vec![
                    CanonicalItem::nonempty_ascii(
                        COLLECTIVE_COIN_SOURCE_BIVARIATE_PRIVATE_ROW_BODY_DOMAIN,
                    )?,
                    CanonicalItem::hash512(self.layout.identity().into_bytes()),
                    CanonicalItem::hash512(self.root_body_identity.into_bytes()),
                    CanonicalItem::unsigned16(self.layout.participant_count()),
                    CanonicalItem::unsigned16(self.layout.contributor_position()),
                    CanonicalItem::unsigned16(self.holder_position),
                    CanonicalItem::unsigned16(u16::try_from(self.openings.len()).map_err(
                        |_| CollectiveCoinSourceBivariateCommitmentError320::IntegerConversion,
                    )?),
                    CanonicalItem::fixed_bytes(payload.as_slice())?,
                ],
            )
            .encode()?,
        ))
    }

    fn from_canonical_bytes(
        authenticated_root: &AuthorAuthenticatedCollectiveCoinSourceBivariateCommitmentRoot320,
        bytes: &[u8],
    ) -> Result<Self, CollectiveCoinSourceBivariateCommitmentError320> {
        let layout = authenticated_root.root_body().layout();
        let tuple = Zeroizing::new(CanonicalTuple::decode(
            bytes,
            &private_row_body_decode_limits(),
        )?);
        require_object_header(
            &tuple,
            COLLECTIVE_COIN_SOURCE_BIVARIATE_PRIVATE_ROW_BODY_DOMAIN,
            PRIVATE_ROW_BODY_ITEM_COUNT,
        )?;
        require_hash(&tuple.items[1], layout.identity(), "layout identity")?;
        require_hash(
            &tuple.items[2],
            authenticated_root.root_body_identity(),
            "root-body identity",
        )?;
        require_u16(
            &tuple.items[3],
            layout.participant_count(),
            "participant count",
        )?;
        require_u16(
            &tuple.items[4],
            layout.contributor_position(),
            "contributor position",
        )?;
        let holder_position = read_u16(&tuple.items[5], "holder position")?;
        layout.validate_holder_position(holder_position)?;
        let expected_opening_count = usize::from(layout.participant_count())
            .checked_mul(CollectiveCoinSourceComponent320::ALL.len())
            .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)?;
        require_u16(
            &tuple.items[6],
            u16::try_from(expected_opening_count)
                .map_err(|_| CollectiveCoinSourceBivariateCommitmentError320::IntegerConversion)?,
            "field-value count",
        )?;
        if tuple.items[7].item_type() != CanonicalItemType::RawBytes {
            return Err(collective_coin_commitment_object_mismatch(
                "private row payload",
            ));
        }
        let payload = tuple.items[7].canonical_bytes();
        let expected_payload_byte_length =
            private_row_payload_byte_length(layout.participant_count())?;
        if payload.len() != expected_payload_byte_length {
            return Err(
                CollectiveCoinSourceBivariateCommitmentError320::PrivateRowPayloadByteLength {
                    expected: expected_payload_byte_length,
                    actual: payload.len(),
                },
            );
        }
        let coordinates = layout.holder_coordinates(holder_position)?;
        let mut openings = Vec::with_capacity(coordinates.len());
        for (coordinate, opening_bytes) in coordinates.into_iter().zip(payload.chunks_exact(
            BinaryFieldElement320::CANONICAL_BYTE_LENGTH
                + COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH,
        )) {
            let value = BinaryFieldElement320::from_canonical_bytes(
                &opening_bytes[..BinaryFieldElement320::CANONICAL_BYTE_LENGTH],
            )?;
            let salt = opening_bytes[BinaryFieldElement320::CANONICAL_BYTE_LENGTH..]
                .try_into()
                .map_err(|_| collective_coin_commitment_object_mismatch("opening salt"))?;
            openings.push(CollectiveCoinSourceBivariateCommitmentOpening320 {
                coordinate,
                value,
                salt,
            });
        }
        Ok(Self {
            layout,
            root_body_identity: authenticated_root.root_body_identity(),
            holder_position,
            openings,
        })
    }
}

impl fmt::Debug for CollectiveCoinSourceBivariatePrivateRowBody320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectiveCoinSourceBivariatePrivateRowBody320")
            .field("layout", &self.layout)
            .field("root_body_identity", &self.root_body_identity)
            .field("holder_position", &self.holder_position)
            .field("openings", &"[redacted]")
            .finish()
    }
}

/// Positive contributor signature, commitment correspondence, and local
/// degree result. Exact opening bytes are retained for the later authorized
/// public release, but this object has no receipt, challenge, or continuation
/// authority.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedCollectiveCoinSourceBivariatePrivateRow320 {
    root_body_identity: Hash512,
    contributor_position: u16,
    holder_position: u16,
    private_row_body: CollectiveCoinSourceBivariatePrivateRowBody320,
    row: CollectiveCoinSourceBivariateRow320,
}

impl AuthenticatedCollectiveCoinSourceBivariatePrivateRow320 {
    pub(crate) const fn root_body_identity(&self) -> Hash512 {
        self.root_body_identity
    }

    pub(crate) const fn contributor_position(&self) -> u16 {
        self.contributor_position
    }

    pub(crate) const fn holder_position(&self) -> u16 {
        self.holder_position
    }

    pub(crate) const fn row(&self) -> &CollectiveCoinSourceBivariateRow320 {
        &self.row
    }

    pub(crate) fn private_row_body_bytes(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, CollectiveCoinSourceBivariateCommitmentError320> {
        self.private_row_body.canonical_bytes()
    }
}

impl fmt::Debug for AuthenticatedCollectiveCoinSourceBivariatePrivateRow320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedCollectiveCoinSourceBivariatePrivateRow320")
            .field("root_body_identity", &self.root_body_identity)
            .field("contributor_position", &self.contributor_position)
            .field("holder_position", &self.holder_position)
            .field("private_row_body", &"[redacted]")
            .field("row", &"[redacted]")
            .finish()
    }
}

pub(crate) fn verify_collective_coin_source_bivariate_private_row_320(
    authenticated_root: &AuthorAuthenticatedCollectiveCoinSourceBivariateCommitmentRoot320,
    private_row_body_bytes: &[u8],
) -> Result<
    AuthenticatedCollectiveCoinSourceBivariatePrivateRow320,
    CollectiveCoinSourceBivariateCommitmentError320,
> {
    let private_row = CollectiveCoinSourceBivariatePrivateRowBody320::from_canonical_bytes(
        authenticated_root,
        private_row_body_bytes,
    )?;
    let layout = private_row.layout;
    for opening in &private_row.openings {
        let leaf_ordinal = layout.leaf_ordinal(opening.coordinate)?;
        let expected_digest =
            authenticated_root
                .root_body()
                .commitment_digests()
                .get(usize::try_from(leaf_ordinal).map_err(|_| {
                    CollectiveCoinSourceBivariateCommitmentError320::IntegerConversion
                })?)
                .ok_or(collective_coin_commitment_object_mismatch(
                    "commitment digest",
                ))?;
        let actual_digest = opening.digest(layout)?;
        if !bool::from(actual_digest.as_bytes().ct_eq(expected_digest.as_bytes())) {
            return Err(
                CollectiveCoinSourceBivariateCommitmentError320::CommitmentMismatch {
                    leaf_ordinal,
                },
            );
        }
    }

    let holder_position = private_row.holder_position;
    let mut secret_axis_values =
        [BinaryFieldElement320::ZERO; CollectiveCoinSourceComponent320::ALL.len()];
    let peer_holder_positions = (0..layout.participant_count())
        .filter(|position| *position != holder_position)
        .collect::<Vec<_>>();
    let mut crosspoint_component_values = vec![
        [BinaryFieldElement320::ZERO;
            CollectiveCoinSourceComponent320::ALL.len()];
        peer_holder_positions.len()
    ];
    let mut opening_position = 0_usize;
    for component in CollectiveCoinSourceComponent320::ALL {
        let secret_axis_opening = private_row.openings.get(opening_position).ok_or(
            collective_coin_commitment_object_mismatch("secret-axis opening"),
        )?;
        let expected_secret_axis_coordinate =
            CollectiveCoinSourceBivariateCommitmentCoordinate320::SecretAxis {
                component,
                holder_position,
            };
        if secret_axis_opening.coordinate != expected_secret_axis_coordinate {
            return Err(collective_coin_commitment_object_mismatch(
                "secret-axis coordinate",
            ));
        }
        secret_axis_values[component.position()] = secret_axis_opening.value;
        opening_position += 1;
        for (peer_offset, peer_holder_position) in peer_holder_positions.iter().copied().enumerate()
        {
            let opening = private_row.openings.get(opening_position).ok_or(
                collective_coin_commitment_object_mismatch("crosspoint opening"),
            )?;
            let expected_crosspoint_coordinate =
                CollectiveCoinSourceBivariateCommitmentCoordinate320::Crosspoint {
                    component,
                    lower_holder_position: holder_position.min(peer_holder_position),
                    upper_holder_position: holder_position.max(peer_holder_position),
                };
            if opening.coordinate != expected_crosspoint_coordinate {
                return Err(collective_coin_commitment_object_mismatch(
                    "crosspoint coordinate",
                ));
            }
            crosspoint_component_values[peer_offset][component.position()] = opening.value;
            opening_position += 1;
        }
    }
    if opening_position != private_row.openings.len() {
        return Err(collective_coin_commitment_object_mismatch(
            "private row opening count",
        ));
    }
    let crosspoints = peer_holder_positions
        .into_iter()
        .zip(crosspoint_component_values)
        .map(|(peer_holder_position, component_values)| {
            Ok(CollectiveCoinSourceBivariateCrosspoint320::from_parts(
                peer_holder_position,
                canonical_evaluation_point_320(layout.participant_count(), peer_holder_position)?,
                component_values,
            ))
        })
        .collect::<Result<Vec<_>, TallyPreparationError>>()?;
    let row = CollectiveCoinSourceBivariateRow320::from_parts(
        layout.participant_count(),
        layout.contributor_position(),
        holder_position,
        canonical_evaluation_point_320(layout.participant_count(), holder_position)?,
        secret_axis_values,
        crosspoints,
    )?;
    for component in CollectiveCoinSourceComponent320::ALL {
        if !row.is_locally_degree_bounded(component, usize::from(layout.reconstruction_threshold()))
        {
            return Err(
                CollectiveCoinSourceBivariateCommitmentError320::LocalRowDegreeMismatch {
                    holder_position,
                    component,
                },
            );
        }
    }
    Ok(AuthenticatedCollectiveCoinSourceBivariatePrivateRow320 {
        root_body_identity: authenticated_root.root_body_identity(),
        contributor_position: layout.contributor_position(),
        holder_position,
        private_row_body: private_row,
        row,
    })
}

pub(crate) fn derive_collective_coin_source_bivariate_commitment_digest_320(
    layout: CollectiveCoinSourceBivariateCommitmentLayout320,
    coordinate: CollectiveCoinSourceBivariateCommitmentCoordinate320,
    value: BinaryFieldElement320,
    salt: [u8; COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH],
) -> Result<Hash512, CollectiveCoinSourceBivariateCommitmentError320> {
    layout.validate_coordinate(coordinate)?;
    let leaf_ordinal = layout.leaf_ordinal(coordinate)?;
    let mut items = vec![
        CanonicalItem::hash512(layout.identity().into_bytes()),
        CanonicalItem::unsigned64(leaf_ordinal),
        CanonicalItem::unsigned16(layout.participant_count()),
        CanonicalItem::unsigned16(layout.contributor_position()),
    ];
    coordinate.append_hash_items(&mut items);
    items.push(CanonicalItem::fixed_bytes(value.canonical_bytes())?);
    items.push(CanonicalItem::fixed_bytes(salt)?);
    Ok(hash_foundation_tuple_512(
        COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_DIGEST_DOMAIN,
        &items,
    )?)
}

fn evaluate_commitment_coordinate(
    layout: CollectiveCoinSourceBivariateCommitmentLayout320,
    polynomial: &CollectiveCoinSourceSymmetricBivariatePolynomial320,
    coordinate: CollectiveCoinSourceBivariateCommitmentCoordinate320,
) -> Result<BinaryFieldElement320, CollectiveCoinSourceBivariateCommitmentError320> {
    layout.validate_coordinate(coordinate)?;
    match coordinate {
        CollectiveCoinSourceBivariateCommitmentCoordinate320::SecretAxis {
            component,
            holder_position,
        } => Ok(polynomial.evaluate(
            component,
            canonical_evaluation_point_320(layout.participant_count(), holder_position)?,
            BinaryFieldElement320::ZERO,
        )),
        CollectiveCoinSourceBivariateCommitmentCoordinate320::Crosspoint {
            component,
            lower_holder_position,
            upper_holder_position,
        } => Ok(polynomial.evaluate(
            component,
            canonical_evaluation_point_320(layout.participant_count(), lower_holder_position)?,
            canonical_evaluation_point_320(layout.participant_count(), upper_holder_position)?,
        )),
    }
}

fn pair_ordinal(
    participant_count: u16,
    lower_holder_position: u16,
    upper_holder_position: u16,
) -> Result<u64, CollectiveCoinSourceBivariateCommitmentError320> {
    let participant_count = u64::from(participant_count);
    let lower_holder_position = u64::from(lower_holder_position);
    let upper_holder_position = u64::from(upper_holder_position);
    let preceding_pair_count = lower_holder_position
        .checked_mul(
            participant_count
                .checked_mul(2)
                .and_then(|twice_count| twice_count.checked_sub(lower_holder_position))
                .and_then(|value| value.checked_sub(1))
                .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)?,
        )
        .and_then(|product| product.checked_div(2))
        .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)?;
    preceding_pair_count
        .checked_add(
            upper_holder_position
                .checked_sub(lower_holder_position)
                .and_then(|distance| distance.checked_sub(1))
                .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)?,
        )
        .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)
}

fn private_row_payload_byte_length(
    participant_count: u16,
) -> Result<usize, CollectiveCoinSourceBivariateCommitmentError320> {
    usize::from(participant_count)
        .checked_mul(CollectiveCoinSourceComponent320::ALL.len())
        .and_then(|field_value_count| {
            field_value_count.checked_mul(
                BinaryFieldElement320::CANONICAL_BYTE_LENGTH
                    + COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH,
            )
        })
        .ok_or(CollectiveCoinSourceBivariateCommitmentError320::ArithmeticOverflow)
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), CollectiveCoinSourceBivariateCommitmentError320> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER {
        return Err(collective_coin_commitment_object_mismatch(
            "schema identifier",
        ));
    }
    if tuple.schema_version != CANONICAL_TUPLE_VERSION {
        return Err(collective_coin_commitment_object_mismatch("schema version"));
    }
    if tuple.items.len() != expected_item_count {
        return Err(collective_coin_commitment_object_mismatch("item count"));
    }
    if tuple.items[0].item_type() != CanonicalItemType::Ascii
        || tuple.items[0].variable_value_bytes()? != expected_domain.as_bytes()
    {
        return Err(collective_coin_commitment_object_mismatch("object domain"));
    }
    Ok(())
}

fn require_hash(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), CollectiveCoinSourceBivariateCommitmentError320> {
    if read_hash(item, field)? != expected {
        return Err(collective_coin_commitment_object_mismatch(field));
    }
    Ok(())
}

fn read_hash(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<Hash512, CollectiveCoinSourceBivariateCommitmentError320> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(collective_coin_commitment_object_mismatch(field));
    }
    Ok(Hash512::from_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| collective_coin_commitment_object_mismatch(field))?,
    ))
}

fn require_u16(
    item: &CanonicalItem,
    expected: u16,
    field: &'static str,
) -> Result<(), CollectiveCoinSourceBivariateCommitmentError320> {
    if read_u16(item, field)? != expected {
        return Err(collective_coin_commitment_object_mismatch(field));
    }
    Ok(())
}

fn read_u16(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u16, CollectiveCoinSourceBivariateCommitmentError320> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(collective_coin_commitment_object_mismatch(field));
    }
    Ok(u16::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| collective_coin_commitment_object_mismatch(field))?,
    ))
}

fn require_u64(
    item: &CanonicalItem,
    expected: u64,
    field: &'static str,
) -> Result<(), CollectiveCoinSourceBivariateCommitmentError320> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(collective_coin_commitment_object_mismatch(field));
    }
    let actual = u64::from_le_bytes(
        item.canonical_bytes()
            .try_into()
            .map_err(|_| collective_coin_commitment_object_mismatch(field))?,
    );
    if actual != expected {
        return Err(collective_coin_commitment_object_mismatch(field));
    }
    Ok(())
}

const fn collective_coin_commitment_object_mismatch(
    field: &'static str,
) -> CollectiveCoinSourceBivariateCommitmentError320 {
    CollectiveCoinSourceBivariateCommitmentError320::ObjectMismatch { field }
}

fn root_body_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_ROOT_BODY_BYTE_LENGTH,
        maximum_item_count: MAXIMUM_ROOT_BODY_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_ROOT_BODY_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_ROOT_BODY_CUMULATIVE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length: MAXIMUM_ROOT_BODY_CUMULATIVE_BYTE_LENGTH,
    }
}

fn signature_envelope_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_SIGNATURE_ENVELOPE_BYTE_LENGTH,
        maximum_item_count: SIGNATURE_ENVELOPE_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_SIGNATURE_ENVELOPE_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_SIGNATURE_ENVELOPE_BYTE_LENGTH,
        maximum_cumulative_allocation_byte_length: MAXIMUM_SIGNATURE_ENVELOPE_BYTE_LENGTH,
    }
}

fn private_row_body_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_PRIVATE_ROW_BODY_BYTE_LENGTH,
        maximum_item_count: PRIVATE_ROW_BODY_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_PRIVATE_ROW_BODY_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: MAXIMUM_PRIVATE_ROW_BODY_BYTE_LENGTH * 2,
        maximum_cumulative_allocation_byte_length: MAXIMUM_PRIVATE_ROW_BODY_BYTE_LENGTH * 2,
    }
}
