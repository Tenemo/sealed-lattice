use core::fmt;

use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple, Hash512,
    ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, Roster, hash_foundation_tuple_512,
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    binary_field_320::BinaryFieldElement320,
    masked_ballot_bivariate_sharing_320::{
        MaskedBallotBivariateCrosspoint320, MaskedBallotBivariateRow320,
        MaskedBallotBivariateSharingError320, MaskedBallotSymmetricBivariatePolynomial320,
    },
    pseudorandom_zero_sharing_320::canonical_evaluation_point_320,
};

const MASKED_BALLOT_BIVARIATE_COMMITMENT_LAYOUT_VERSION: u16 = 1;
const SECRET_AXIS_COORDINATE_KIND_CODE: u8 = 1;
const CROSSPOINT_COORDINATE_KIND_CODE: u8 = 2;
const ROOT_BODY_PREFIX_ITEM_COUNT: usize = 12;
const SIGNATURE_ENVELOPE_ITEM_COUNT: usize = 3;
const PRIVATE_ROW_BODY_ITEM_COUNT: usize = 8;
const MAXIMUM_ROOT_BODY_BYTE_LENGTH: usize = 32 * 1024;
const MAXIMUM_ROOT_BODY_ITEM_COUNT: usize = 256;
const MAXIMUM_ROOT_BODY_ITEM_BYTE_LENGTH: usize = 4 * 1024;
const MAXIMUM_ROOT_BODY_CUMULATIVE_BYTE_LENGTH: usize = 128 * 1024;
const MAXIMUM_SIGNATURE_ENVELOPE_BYTE_LENGTH: usize = 8 * 1024;
const MAXIMUM_SIGNATURE_ENVELOPE_ITEM_BYTE_LENGTH: usize = 4 * 1024;
const MAXIMUM_PRIVATE_ROW_BODY_BYTE_LENGTH: usize = 8 * 1024;
const MAXIMUM_PRIVATE_ROW_BODY_ITEM_BYTE_LENGTH: usize = 4 * 1024;

pub(crate) const MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH: usize = 64;
pub(crate) const MASKED_BALLOT_BIVARIATE_COMMITMENT_LAYOUT_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-commitment-layout-identity";
pub(crate) const MASKED_BALLOT_BIVARIATE_COMMITMENT_DIGEST_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-commitment-digest";
pub(crate) const MASKED_BALLOT_BIVARIATE_COMMITMENT_ROOT_BODY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-commitment-root-body";
pub(crate) const MASKED_BALLOT_BIVARIATE_COMMITMENT_ROOT_BODY_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-commitment-root-body-identity";
pub(crate) const MASKED_BALLOT_BIVARIATE_COMMITMENT_SIGNATURE_CONTEXT: &[u8] =
    b"sealed-lattice/v1/ballot/bivariate-commitment-root";
pub(crate) const MASKED_BALLOT_BIVARIATE_COMMITMENT_SIGNATURE_ENVELOPE_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-commitment-signature-envelope";
pub(crate) const MASKED_BALLOT_BIVARIATE_PRIVATE_ROW_BODY_DOMAIN: &str =
    "sealed-lattice/v1/ballot/bivariate-private-row-body";
pub(crate) const MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH: usize = 3_309;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MaskedBallotBivariateCommitmentError320 {
    Canonical(CanonicalCodecError),
    Preparation(TallyPreparationError),
    Sharing(MaskedBallotBivariateSharingError320),
    UnsupportedRoster {
        participant_count: u16,
    },
    AuthorRosterPositionOutOfRange {
        author_roster_position: u16,
        participant_count: u16,
    },
    HolderRosterPositionOutOfRange {
        holder_roster_position: u16,
        participant_count: u16,
    },
    PolynomialParticipantCountMismatch {
        polynomial_participant_count: u16,
        layout_participant_count: u16,
    },
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
        holder_roster_position: u16,
    },
    RosterMismatch,
    SignatureByteLength {
        expected: usize,
        actual: usize,
    },
    MalformedSigningVerificationKey,
    InvalidSignature,
    ArithmeticOverflow,
}

impl From<CanonicalCodecError> for MaskedBallotBivariateCommitmentError320 {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<TallyPreparationError> for MaskedBallotBivariateCommitmentError320 {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl From<MaskedBallotBivariateSharingError320> for MaskedBallotBivariateCommitmentError320 {
    fn from(error: MaskedBallotBivariateSharingError320) -> Self {
        Self::Sharing(error)
    }
}

impl fmt::Display for MaskedBallotBivariateCommitmentError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => write!(
                formatter,
                "canonical masked-ballot bivariate commitment error: {error}"
            ),
            Self::Preparation(error) => {
                write!(
                    formatter,
                    "masked-ballot commitment preparation error: {error}"
                )
            }
            Self::Sharing(error) => {
                write!(formatter, "masked-ballot commitment sharing error: {error}")
            }
            Self::UnsupportedRoster { participant_count } => write!(
                formatter,
                "participant count {participant_count} does not admit masked-ballot bivariate commitments"
            ),
            Self::AuthorRosterPositionOutOfRange {
                author_roster_position,
                participant_count,
            } => write!(
                formatter,
                "masked-ballot author roster position {author_roster_position} is outside participant count {participant_count}"
            ),
            Self::HolderRosterPositionOutOfRange {
                holder_roster_position,
                participant_count,
            } => write!(
                formatter,
                "masked-ballot holder roster position {holder_roster_position} is outside participant count {participant_count}"
            ),
            Self::PolynomialParticipantCountMismatch {
                polynomial_participant_count,
                layout_participant_count,
            } => write!(
                formatter,
                "masked-ballot polynomial participant count {polynomial_participant_count} does not match commitment layout count {layout_participant_count}"
            ),
            Self::SaltCountMismatch { expected, actual } => write!(
                formatter,
                "masked-ballot commitment source has {actual} salts; expected {expected}"
            ),
            Self::CommitmentDigestCountMismatch { expected, actual } => write!(
                formatter,
                "masked-ballot commitment root has {actual} digests; expected {expected}"
            ),
            Self::ObjectMismatch { field } => {
                write!(
                    formatter,
                    "masked-ballot commitment object has a wrong {field}"
                )
            }
            Self::PrivateRowPayloadByteLength { expected, actual } => write!(
                formatter,
                "masked-ballot private row payload has {actual} bytes; expected {expected}"
            ),
            Self::CommitmentMismatch { leaf_ordinal } => write!(
                formatter,
                "masked-ballot private row opening does not match commitment leaf {leaf_ordinal}"
            ),
            Self::LocalRowDegreeMismatch {
                holder_roster_position,
            } => write!(
                formatter,
                "masked-ballot private row for holder {holder_roster_position} is not locally degree bounded"
            ),
            Self::RosterMismatch => formatter.write_str(
                "masked-ballot commitment roster does not match the preparation context",
            ),
            Self::SignatureByteLength { expected, actual } => write!(
                formatter,
                "masked-ballot root signature has {actual} bytes; expected {expected}"
            ),
            Self::MalformedSigningVerificationKey => formatter
                .write_str("masked-ballot author has a malformed ML-DSA-65 verification key"),
            Self::InvalidSignature => {
                formatter.write_str("masked-ballot commitment root has an invalid signature")
            }
            Self::ArithmeticOverflow => {
                formatter.write_str("masked-ballot commitment arithmetic overflow")
            }
        }
    }
}

impl std::error::Error for MaskedBallotBivariateCommitmentError320 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::Preparation(error) => Some(error),
            Self::Sharing(error) => Some(error),
            Self::UnsupportedRoster { .. }
            | Self::AuthorRosterPositionOutOfRange { .. }
            | Self::HolderRosterPositionOutOfRange { .. }
            | Self::PolynomialParticipantCountMismatch { .. }
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
            | Self::ArithmeticOverflow => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum MaskedBallotBivariateCommitmentCoordinate320 {
    SecretAxis {
        holder_roster_position: u16,
    },
    Crosspoint {
        lower_holder_roster_position: u16,
        upper_holder_roster_position: u16,
    },
}

impl MaskedBallotBivariateCommitmentCoordinate320 {
    const fn kind_code(self) -> u8 {
        match self {
            Self::SecretAxis { .. } => SECRET_AXIS_COORDINATE_KIND_CODE,
            Self::Crosspoint { .. } => CROSSPOINT_COORDINATE_KIND_CODE,
        }
    }

    fn append_hash_items(self, items: &mut Vec<CanonicalItem>) {
        items.push(CanonicalItem::unsigned8(self.kind_code()));
        match self {
            Self::SecretAxis {
                holder_roster_position,
            } => items.push(CanonicalItem::unsigned16(holder_roster_position)),
            Self::Crosspoint {
                lower_holder_roster_position,
                upper_holder_roster_position,
            } => {
                items.push(CanonicalItem::unsigned16(lower_holder_roster_position));
                items.push(CanonicalItem::unsigned16(upper_holder_roster_position));
            }
        }
    }
}

/// Value-independent owner of the exact flat commitment inventory.
///
/// The first `n` leaves bind `F(e_i, 0)` in roster order. The remaining leaves
/// bind `F(e_i, e_j)` for `i < j` in lexicographic pair order. A flat digest
/// inventory is smaller than repeating a Merkle path in all ten private rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateCommitmentLayout320 {
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    preparation_record_identity: Hash512,
    author_roster_position: u16,
    reconstruction_threshold: u16,
    secret_axis_leaf_count: u64,
    crosspoint_leaf_count: u64,
    leaf_count: u64,
    identity: Hash512,
}

impl MaskedBallotBivariateCommitmentLayout320 {
    pub(crate) fn derive(
        parameter_identity: Hash512,
        preparation_context: TallyPreparationContext,
        preparation_record_identity: Hash512,
        author_roster_position: u16,
    ) -> Result<Self, MaskedBallotBivariateCommitmentError320> {
        let participant_count = preparation_context.participant_count();
        let roster_parameters = crate::foundation::derive_foundation_roster_parameters(
            participant_count,
        )
        .ok_or(MaskedBallotBivariateCommitmentError320::UnsupportedRoster { participant_count })?;
        if author_roster_position >= participant_count {
            return Err(
                MaskedBallotBivariateCommitmentError320::AuthorRosterPositionOutOfRange {
                    author_roster_position,
                    participant_count,
                },
            );
        }
        let secret_axis_leaf_count = u64::from(participant_count);
        let crosspoint_leaf_count = secret_axis_leaf_count
            .checked_mul(
                secret_axis_leaf_count
                    .checked_sub(1)
                    .ok_or(MaskedBallotBivariateCommitmentError320::ArithmeticOverflow)?,
            )
            .and_then(|ordered_pair_count| ordered_pair_count.checked_div(2))
            .ok_or(MaskedBallotBivariateCommitmentError320::ArithmeticOverflow)?;
        let leaf_count = secret_axis_leaf_count
            .checked_add(crosspoint_leaf_count)
            .ok_or(MaskedBallotBivariateCommitmentError320::ArithmeticOverflow)?;
        let reconstruction_threshold = roster_parameters.reconstruction_threshold;
        let identity = hash_foundation_tuple_512(
            MASKED_BALLOT_BIVARIATE_COMMITMENT_LAYOUT_IDENTITY_DOMAIN,
            &[
                CanonicalItem::unsigned16(MASKED_BALLOT_BIVARIATE_COMMITMENT_LAYOUT_VERSION),
                CanonicalItem::hash512(parameter_identity.into_bytes()),
                CanonicalItem::hash512(preparation_context.identity().into_bytes()),
                CanonicalItem::hash512(preparation_record_identity.into_bytes()),
                CanonicalItem::unsigned16(participant_count),
                CanonicalItem::unsigned16(author_roster_position),
                CanonicalItem::unsigned16(reconstruction_threshold),
                CanonicalItem::unsigned64(secret_axis_leaf_count),
                CanonicalItem::unsigned64(crosspoint_leaf_count),
                CanonicalItem::unsigned64(leaf_count),
            ],
        )?;
        Ok(Self {
            parameter_identity,
            preparation_context,
            preparation_record_identity,
            author_roster_position,
            reconstruction_threshold,
            secret_axis_leaf_count,
            crosspoint_leaf_count,
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

    pub(crate) const fn preparation_record_identity(self) -> Hash512 {
        self.preparation_record_identity
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.preparation_context.participant_count()
    }

    pub(crate) const fn author_roster_position(self) -> u16 {
        self.author_roster_position
    }

    pub(crate) const fn reconstruction_threshold(self) -> u16 {
        self.reconstruction_threshold
    }

    pub(crate) const fn secret_axis_leaf_count(self) -> u64 {
        self.secret_axis_leaf_count
    }

    pub(crate) const fn crosspoint_leaf_count(self) -> u64 {
        self.crosspoint_leaf_count
    }

    pub(crate) const fn leaf_count(self) -> u64 {
        self.leaf_count
    }

    pub(crate) const fn identity(self) -> Hash512 {
        self.identity
    }

    pub(crate) fn coordinates(self) -> Vec<MaskedBallotBivariateCommitmentCoordinate320> {
        let mut coordinates = Vec::with_capacity(
            usize::try_from(self.leaf_count).expect("admitted ballot commitment count fits usize"),
        );
        for holder_roster_position in 0..self.participant_count() {
            coordinates.push(MaskedBallotBivariateCommitmentCoordinate320::SecretAxis {
                holder_roster_position,
            });
        }
        for lower_holder_roster_position in 0..self.participant_count() {
            for upper_holder_roster_position in
                lower_holder_roster_position + 1..self.participant_count()
            {
                coordinates.push(MaskedBallotBivariateCommitmentCoordinate320::Crosspoint {
                    lower_holder_roster_position,
                    upper_holder_roster_position,
                });
            }
        }
        coordinates
    }

    pub(crate) fn holder_coordinates(
        self,
        holder_roster_position: u16,
    ) -> Result<
        Vec<MaskedBallotBivariateCommitmentCoordinate320>,
        MaskedBallotBivariateCommitmentError320,
    > {
        self.validate_holder_roster_position(holder_roster_position)?;
        let mut coordinates = Vec::with_capacity(usize::from(self.participant_count()));
        coordinates.push(MaskedBallotBivariateCommitmentCoordinate320::SecretAxis {
            holder_roster_position,
        });
        for peer_roster_position in 0..self.participant_count() {
            if peer_roster_position == holder_roster_position {
                continue;
            }
            coordinates.push(MaskedBallotBivariateCommitmentCoordinate320::Crosspoint {
                lower_holder_roster_position: holder_roster_position.min(peer_roster_position),
                upper_holder_roster_position: holder_roster_position.max(peer_roster_position),
            });
        }
        Ok(coordinates)
    }

    pub(crate) fn leaf_ordinal(
        self,
        coordinate: MaskedBallotBivariateCommitmentCoordinate320,
    ) -> Result<u64, MaskedBallotBivariateCommitmentError320> {
        self.validate_coordinate(coordinate)?;
        self.coordinates()
            .into_iter()
            .position(|candidate| candidate == coordinate)
            .ok_or(masked_ballot_commitment_object_mismatch(
                "commitment coordinate",
            ))
            .and_then(|position| {
                u64::try_from(position)
                    .map_err(|_| MaskedBallotBivariateCommitmentError320::ArithmeticOverflow)
            })
    }

    fn validate_coordinate(
        self,
        coordinate: MaskedBallotBivariateCommitmentCoordinate320,
    ) -> Result<(), MaskedBallotBivariateCommitmentError320> {
        match coordinate {
            MaskedBallotBivariateCommitmentCoordinate320::SecretAxis {
                holder_roster_position,
            } => self.validate_holder_roster_position(holder_roster_position),
            MaskedBallotBivariateCommitmentCoordinate320::Crosspoint {
                lower_holder_roster_position,
                upper_holder_roster_position,
            } => {
                if lower_holder_roster_position >= upper_holder_roster_position
                    || upper_holder_roster_position >= self.participant_count()
                {
                    return Err(masked_ballot_commitment_object_mismatch(
                        "commitment coordinate",
                    ));
                }
                Ok(())
            }
        }
    }

    fn validate_holder_roster_position(
        self,
        holder_roster_position: u16,
    ) -> Result<(), MaskedBallotBivariateCommitmentError320> {
        if holder_roster_position >= self.participant_count() {
            return Err(
                MaskedBallotBivariateCommitmentError320::HolderRosterPositionOutOfRange {
                    holder_roster_position,
                    participant_count: self.participant_count(),
                },
            );
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct MaskedBallotBivariateCommitmentOpening320 {
    coordinate: MaskedBallotBivariateCommitmentCoordinate320,
    value: BinaryFieldElement320,
    salt: [u8; MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH],
}

impl MaskedBallotBivariateCommitmentOpening320 {
    fn digest(
        &self,
        layout: MaskedBallotBivariateCommitmentLayout320,
    ) -> Result<Hash512, MaskedBallotBivariateCommitmentError320> {
        derive_masked_ballot_bivariate_commitment_digest_320(
            layout,
            self.coordinate,
            self.value,
            self.salt,
        )
    }
}

impl fmt::Debug for MaskedBallotBivariateCommitmentOpening320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariateCommitmentOpening320")
            .field("coordinate", &self.coordinate)
            .field("value", &"[redacted]")
            .field("salt", &"[redacted]")
            .finish()
    }
}

impl Drop for MaskedBallotBivariateCommitmentOpening320 {
    fn drop(&mut self) {
        self.value.zeroize();
        self.salt.zeroize();
    }
}

/// Public flat digest inventory authenticated separately by the ballot author.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateCommitmentRootBody320 {
    layout: MaskedBallotBivariateCommitmentLayout320,
    commitment_digests: Box<[Hash512]>,
}

impl MaskedBallotBivariateCommitmentRootBody320 {
    pub(crate) fn new(
        layout: MaskedBallotBivariateCommitmentLayout320,
        commitment_digests: Vec<Hash512>,
    ) -> Result<Self, MaskedBallotBivariateCommitmentError320> {
        let expected = usize::try_from(layout.leaf_count())
            .map_err(|_| MaskedBallotBivariateCommitmentError320::ArithmeticOverflow)?;
        if commitment_digests.len() != expected {
            return Err(
                MaskedBallotBivariateCommitmentError320::CommitmentDigestCountMismatch {
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

    pub(crate) const fn layout(&self) -> MaskedBallotBivariateCommitmentLayout320 {
        self.layout
    }

    pub(crate) fn commitment_digests(&self) -> &[Hash512] {
        &self.commitment_digests
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, MaskedBallotBivariateCommitmentError320> {
        let mut items =
            Vec::with_capacity(ROOT_BODY_PREFIX_ITEM_COUNT + self.commitment_digests.len());
        items.extend([
            CanonicalItem::nonempty_ascii(MASKED_BALLOT_BIVARIATE_COMMITMENT_ROOT_BODY_DOMAIN)?,
            CanonicalItem::hash512(self.layout.parameter_identity().into_bytes()),
            CanonicalItem::hash512(self.layout.preparation_context().identity().into_bytes()),
            CanonicalItem::hash512(self.layout.preparation_record_identity().into_bytes()),
            CanonicalItem::unsigned16(MASKED_BALLOT_BIVARIATE_COMMITMENT_LAYOUT_VERSION),
            CanonicalItem::hash512(self.layout.identity().into_bytes()),
            CanonicalItem::unsigned16(self.layout.participant_count()),
            CanonicalItem::unsigned16(self.layout.author_roster_position()),
            CanonicalItem::unsigned16(self.layout.reconstruction_threshold()),
            CanonicalItem::unsigned64(self.layout.secret_axis_leaf_count()),
            CanonicalItem::unsigned64(self.layout.crosspoint_leaf_count()),
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

    pub(crate) fn identity(&self) -> Result<Hash512, MaskedBallotBivariateCommitmentError320> {
        Ok(hash_foundation_tuple_512(
            MASKED_BALLOT_BIVARIATE_COMMITMENT_ROOT_BODY_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(self.canonical_bytes()?)?],
        )?)
    }

    fn from_canonical_bytes(
        expected_layout: MaskedBallotBivariateCommitmentLayout320,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateCommitmentError320> {
        let tuple = CanonicalTuple::decode(bytes, &root_body_decode_limits())?;
        let expected_digest_count = usize::try_from(expected_layout.leaf_count())
            .map_err(|_| MaskedBallotBivariateCommitmentError320::ArithmeticOverflow)?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_COMMITMENT_ROOT_BODY_DOMAIN,
            ROOT_BODY_PREFIX_ITEM_COUNT
                .checked_add(expected_digest_count)
                .ok_or(MaskedBallotBivariateCommitmentError320::ArithmeticOverflow)?,
        )?;
        require_hash(
            &tuple.items[1],
            expected_layout.parameter_identity(),
            "parameter identity",
        )?;
        require_hash(
            &tuple.items[2],
            expected_layout.preparation_context().identity(),
            "preparation context identity",
        )?;
        require_hash(
            &tuple.items[3],
            expected_layout.preparation_record_identity(),
            "preparation record identity",
        )?;
        require_u16(
            &tuple.items[4],
            MASKED_BALLOT_BIVARIATE_COMMITMENT_LAYOUT_VERSION,
            "layout version",
        )?;
        require_hash(
            &tuple.items[5],
            expected_layout.identity(),
            "layout identity",
        )?;
        require_u16(
            &tuple.items[6],
            expected_layout.participant_count(),
            "participant count",
        )?;
        require_u16(
            &tuple.items[7],
            expected_layout.author_roster_position(),
            "author roster position",
        )?;
        require_u16(
            &tuple.items[8],
            expected_layout.reconstruction_threshold(),
            "reconstruction threshold",
        )?;
        require_u64(
            &tuple.items[9],
            expected_layout.secret_axis_leaf_count(),
            "secret-axis leaf count",
        )?;
        require_u64(
            &tuple.items[10],
            expected_layout.crosspoint_leaf_count(),
            "crosspoint leaf count",
        )?;
        require_u64(&tuple.items[11], expected_layout.leaf_count(), "leaf count")?;
        let commitment_digests = tuple.items[ROOT_BODY_PREFIX_ITEM_COUNT..]
            .iter()
            .map(|item| read_hash(item, "commitment digest"))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(expected_layout, commitment_digests)
    }
}

/// Producer-side retained source for one fixed-shape ballot custody package.
///
/// The source authenticates no signature, receipt, selected set, or state. Its
/// retained values and salts are erased when the inventory is dropped.
#[derive(PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateCommitmentInventory320 {
    root_body: MaskedBallotBivariateCommitmentRootBody320,
    openings: Vec<MaskedBallotBivariateCommitmentOpening320>,
}

impl MaskedBallotBivariateCommitmentInventory320 {
    pub(crate) fn create(
        layout: MaskedBallotBivariateCommitmentLayout320,
        polynomial: &MaskedBallotSymmetricBivariatePolynomial320,
        salts: Vec<[u8; MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH]>,
    ) -> Result<Self, MaskedBallotBivariateCommitmentError320> {
        let mut salts = Zeroizing::new(salts);
        if polynomial.participant_count() != layout.participant_count() {
            return Err(
                MaskedBallotBivariateCommitmentError320::PolynomialParticipantCountMismatch {
                    polynomial_participant_count: polynomial.participant_count(),
                    layout_participant_count: layout.participant_count(),
                },
            );
        }
        let coordinates = layout.coordinates();
        if salts.len() != coordinates.len() {
            let actual = salts.len();
            return Err(MaskedBallotBivariateCommitmentError320::SaltCountMismatch {
                expected: coordinates.len(),
                actual,
            });
        }
        let mut openings = Vec::with_capacity(coordinates.len());
        for (coordinate, source_salt) in coordinates.into_iter().zip(salts.iter_mut()) {
            let value = evaluate_commitment_coordinate(layout, polynomial, coordinate)?;
            let salt = *source_salt;
            source_salt.zeroize();
            openings.push(MaskedBallotBivariateCommitmentOpening320 {
                coordinate,
                value,
                salt,
            });
        }
        let commitment_digests = openings
            .iter()
            .map(|opening| opening.digest(layout))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            root_body: MaskedBallotBivariateCommitmentRootBody320::new(layout, commitment_digests)?,
            openings,
        })
    }

    pub(crate) const fn root_body(&self) -> &MaskedBallotBivariateCommitmentRootBody320 {
        &self.root_body
    }

    pub(crate) fn private_row_body(
        &self,
        holder_roster_position: u16,
    ) -> Result<MaskedBallotBivariatePrivateRowBody320, MaskedBallotBivariateCommitmentError320>
    {
        let layout = self.root_body.layout();
        let mut row_openings = Vec::with_capacity(usize::from(layout.participant_count()));
        for coordinate in layout.holder_coordinates(holder_roster_position)? {
            let leaf_ordinal = usize::try_from(layout.leaf_ordinal(coordinate)?)
                .map_err(|_| MaskedBallotBivariateCommitmentError320::ArithmeticOverflow)?;
            let opening = self
                .openings
                .get(leaf_ordinal)
                .ok_or(masked_ballot_commitment_object_mismatch("retained opening"))?;
            if opening.coordinate != coordinate {
                return Err(masked_ballot_commitment_object_mismatch(
                    "retained opening coordinate",
                ));
            }
            row_openings.push(opening.clone());
        }
        Ok(MaskedBallotBivariatePrivateRowBody320 {
            layout,
            root_body_identity: self.root_body.identity()?,
            holder_roster_position,
            openings: row_openings,
        })
    }
}

impl fmt::Debug for MaskedBallotBivariateCommitmentInventory320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariateCommitmentInventory320")
            .field("root_body", &self.root_body)
            .field("openings", &"[redacted]")
            .finish()
    }
}

/// Detached author signature over the exact canonical root body.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateCommitmentSignatureEnvelope320 {
    root_body_identity: Hash512,
    signature: [u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
}

impl MaskedBallotBivariateCommitmentSignatureEnvelope320 {
    pub(crate) const fn new(
        root_body_identity: Hash512,
        signature: [u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH],
    ) -> Self {
        Self {
            root_body_identity,
            signature,
        }
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, MaskedBallotBivariateCommitmentError320> {
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(
                    MASKED_BALLOT_BIVARIATE_COMMITMENT_SIGNATURE_ENVELOPE_DOMAIN,
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
    ) -> Result<Self, MaskedBallotBivariateCommitmentError320> {
        let tuple = CanonicalTuple::decode(bytes, &signature_envelope_decode_limits())?;
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_COMMITMENT_SIGNATURE_ENVELOPE_DOMAIN,
            SIGNATURE_ENVELOPE_ITEM_COUNT,
        )?;
        require_hash(
            &tuple.items[1],
            expected_root_body_identity,
            "root-body identity",
        )?;
        if tuple.items[2].item_type() != CanonicalItemType::RawBytes {
            return Err(masked_ballot_commitment_object_mismatch("signature"));
        }
        let signature = <[u8; MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH]>::try_from(
            tuple.items[2].canonical_bytes(),
        )
        .map_err(
            |_| MaskedBallotBivariateCommitmentError320::SignatureByteLength {
                expected: MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH,
                actual: tuple.items[2].canonical_bytes().len(),
            },
        )?;
        Ok(Self {
            root_body_identity: expected_root_body_identity,
            signature,
        })
    }
}

impl fmt::Debug for MaskedBallotBivariateCommitmentSignatureEnvelope320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariateCommitmentSignatureEnvelope320")
            .field("root_body_identity", &self.root_body_identity)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Positive author-signature result for one exact flat commitment inventory.
///
/// The expected preparation-record identity is only matched to caller-supplied
/// layout bytes. This result does not prove the preparation record, any private
/// delivery, receipt, state transition, selected set, or release authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320 {
    root_body: MaskedBallotBivariateCommitmentRootBody320,
    root_body_identity: Hash512,
}

impl AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320 {
    pub(crate) const fn root_body(&self) -> &MaskedBallotBivariateCommitmentRootBody320 {
        &self.root_body
    }

    pub(crate) const fn root_body_identity(&self) -> Hash512 {
        self.root_body_identity
    }
}

pub(crate) fn verify_masked_ballot_bivariate_commitment_root_signature_320(
    expected_layout: MaskedBallotBivariateCommitmentLayout320,
    root_body_bytes: &[u8],
    roster: &Roster,
    signature_envelope_bytes: &[u8],
) -> Result<
    AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    MaskedBallotBivariateCommitmentError320,
> {
    let root_body = MaskedBallotBivariateCommitmentRootBody320::from_canonical_bytes(
        expected_layout,
        root_body_bytes,
    )?;
    roster
        .validate()
        .map_err(|_| MaskedBallotBivariateCommitmentError320::RosterMismatch)?;
    if roster.entries.len() != usize::from(expected_layout.participant_count())
        || roster
            .roster_hash()
            .map_err(|_| MaskedBallotBivariateCommitmentError320::RosterMismatch)?
            != expected_layout.preparation_context().roster_hash()
    {
        return Err(MaskedBallotBivariateCommitmentError320::RosterMismatch);
    }
    let root_body_identity = root_body.identity()?;
    let signature_envelope =
        MaskedBallotBivariateCommitmentSignatureEnvelope320::from_canonical_bytes(
            root_body_identity,
            signature_envelope_bytes,
        )?;
    let author_roster_position = expected_layout.author_roster_position();
    let author_roster_entry = roster
        .entries
        .get(usize::from(author_roster_position))
        .ok_or(MaskedBallotBivariateCommitmentError320::RosterMismatch)?;
    if author_roster_entry.roster_position != author_roster_position {
        return Err(MaskedBallotBivariateCommitmentError320::RosterMismatch);
    }
    let verification_key =
        ml_dsa_65::PublicKey::try_from_bytes(author_roster_entry.signing_verification_key)
            .map_err(|_| {
                MaskedBallotBivariateCommitmentError320::MalformedSigningVerificationKey
            })?;
    if !verification_key.verify(
        root_body_bytes,
        &signature_envelope.signature,
        MASKED_BALLOT_BIVARIATE_COMMITMENT_SIGNATURE_CONTEXT,
    ) {
        return Err(MaskedBallotBivariateCommitmentError320::InvalidSignature);
    }
    Ok(AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320 {
        root_body,
        root_body_identity,
    })
}

/// Fixed-shape plaintext delivered privately to one holder.
///
/// Coordinates are implicit: the secret-axis opening comes first, followed by
/// one crosspoint for every peer in roster order. Each entry is exactly a
/// 40-byte field element followed by its independent 64-byte salt.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariatePrivateRowBody320 {
    layout: MaskedBallotBivariateCommitmentLayout320,
    root_body_identity: Hash512,
    holder_roster_position: u16,
    openings: Vec<MaskedBallotBivariateCommitmentOpening320>,
}

impl MaskedBallotBivariatePrivateRowBody320 {
    pub(crate) const fn holder_roster_position(&self) -> u16 {
        self.holder_roster_position
    }

    pub(crate) fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, MaskedBallotBivariateCommitmentError320> {
        let mut payload = Zeroizing::new(Vec::with_capacity(private_row_payload_byte_length(
            self.layout.participant_count(),
        )?));
        for opening in &self.openings {
            payload.extend_from_slice(&opening.value.canonical_bytes());
            payload.extend_from_slice(&opening.salt);
        }
        Ok(CanonicalTuple::new(
            CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
            CANONICAL_TUPLE_VERSION,
            vec![
                CanonicalItem::nonempty_ascii(MASKED_BALLOT_BIVARIATE_PRIVATE_ROW_BODY_DOMAIN)?,
                CanonicalItem::hash512(self.layout.identity().into_bytes()),
                CanonicalItem::hash512(self.root_body_identity.into_bytes()),
                CanonicalItem::unsigned16(self.layout.participant_count()),
                CanonicalItem::unsigned16(self.layout.author_roster_position()),
                CanonicalItem::unsigned16(self.holder_roster_position),
                CanonicalItem::unsigned16(
                    u16::try_from(self.openings.len())
                        .map_err(|_| MaskedBallotBivariateCommitmentError320::ArithmeticOverflow)?,
                ),
                CanonicalItem::fixed_bytes(payload.as_slice())?,
            ],
        )
        .encode()?)
    }

    fn from_canonical_bytes(
        authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
        bytes: &[u8],
    ) -> Result<Self, MaskedBallotBivariateCommitmentError320> {
        let layout = authenticated_root.root_body().layout();
        let tuple = Zeroizing::new(CanonicalTuple::decode(
            bytes,
            &private_row_body_decode_limits(),
        )?);
        require_object_header(
            &tuple,
            MASKED_BALLOT_BIVARIATE_PRIVATE_ROW_BODY_DOMAIN,
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
            layout.author_roster_position(),
            "author roster position",
        )?;
        let holder_roster_position = read_u16(&tuple.items[5], "holder roster position")?;
        layout.validate_holder_roster_position(holder_roster_position)?;
        require_u16(
            &tuple.items[6],
            layout.participant_count(),
            "field-value count",
        )?;
        if tuple.items[7].item_type() != CanonicalItemType::RawBytes {
            return Err(masked_ballot_commitment_object_mismatch(
                "private row payload",
            ));
        }
        let payload = tuple.items[7].canonical_bytes();
        let expected_payload_byte_length =
            private_row_payload_byte_length(layout.participant_count())?;
        if payload.len() != expected_payload_byte_length {
            return Err(
                MaskedBallotBivariateCommitmentError320::PrivateRowPayloadByteLength {
                    expected: expected_payload_byte_length,
                    actual: payload.len(),
                },
            );
        }
        let coordinates = layout.holder_coordinates(holder_roster_position)?;
        let mut openings = Vec::with_capacity(coordinates.len());
        for (coordinate, opening_bytes) in coordinates.into_iter().zip(payload.chunks_exact(
            BinaryFieldElement320::CANONICAL_BYTE_LENGTH
                + MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH,
        )) {
            let value = BinaryFieldElement320::from_canonical_bytes(
                &opening_bytes[..BinaryFieldElement320::CANONICAL_BYTE_LENGTH],
            )?;
            let salt = opening_bytes[BinaryFieldElement320::CANONICAL_BYTE_LENGTH..]
                .try_into()
                .map_err(|_| masked_ballot_commitment_object_mismatch("opening salt"))?;
            openings.push(MaskedBallotBivariateCommitmentOpening320 {
                coordinate,
                value,
                salt,
            });
        }
        Ok(Self {
            layout,
            root_body_identity: authenticated_root.root_body_identity(),
            holder_roster_position,
            openings,
        })
    }
}

impl fmt::Debug for MaskedBallotBivariatePrivateRowBody320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariatePrivateRowBody320")
            .field("layout", &self.layout)
            .field("root_body_identity", &self.root_body_identity)
            .field("holder_roster_position", &self.holder_roster_position)
            .field("openings", &"[redacted]")
            .finish()
    }
}

/// Positive author-signature, commitment-correspondence, and local-degree
/// result for one private row.
///
/// It remains a local custody prerequisite only. It does not prove the named
/// preparation record, an all-roster receipt terminal, or any selected-set or
/// release authority.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedMaskedBallotBivariatePrivateRow320 {
    root_body_identity: Hash512,
    author_roster_position: u16,
    holder_roster_position: u16,
    row: MaskedBallotBivariateRow320,
}

impl AuthenticatedMaskedBallotBivariatePrivateRow320 {
    pub(crate) const fn root_body_identity(&self) -> Hash512 {
        self.root_body_identity
    }

    pub(crate) const fn author_roster_position(&self) -> u16 {
        self.author_roster_position
    }

    pub(crate) const fn holder_roster_position(&self) -> u16 {
        self.holder_roster_position
    }

    pub(crate) const fn row(&self) -> &MaskedBallotBivariateRow320 {
        &self.row
    }
}

impl fmt::Debug for AuthenticatedMaskedBallotBivariatePrivateRow320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedMaskedBallotBivariatePrivateRow320")
            .field("root_body_identity", &self.root_body_identity)
            .field("author_roster_position", &self.author_roster_position)
            .field("holder_roster_position", &self.holder_roster_position)
            .field("row", &"[redacted]")
            .finish()
    }
}

pub(crate) fn verify_masked_ballot_bivariate_private_row_320(
    authenticated_root: &AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
    private_row_body_bytes: &[u8],
) -> Result<AuthenticatedMaskedBallotBivariatePrivateRow320, MaskedBallotBivariateCommitmentError320>
{
    let private_row = MaskedBallotBivariatePrivateRowBody320::from_canonical_bytes(
        authenticated_root,
        private_row_body_bytes,
    )?;
    let layout = private_row.layout;
    for opening in &private_row.openings {
        let leaf_ordinal = layout.leaf_ordinal(opening.coordinate)?;
        let expected_digest = authenticated_root
            .root_body()
            .commitment_digests()
            .get(
                usize::try_from(leaf_ordinal)
                    .map_err(|_| MaskedBallotBivariateCommitmentError320::ArithmeticOverflow)?,
            )
            .ok_or(masked_ballot_commitment_object_mismatch(
                "commitment digest",
            ))?;
        let actual_digest = opening.digest(layout)?;
        if !bool::from(actual_digest.as_bytes().ct_eq(expected_digest.as_bytes())) {
            return Err(
                MaskedBallotBivariateCommitmentError320::CommitmentMismatch { leaf_ordinal },
            );
        }
    }
    let mut opening_iterator = private_row.openings.iter();
    let secret_axis_opening =
        opening_iterator
            .next()
            .ok_or(masked_ballot_commitment_object_mismatch(
                "secret-axis opening",
            ))?;
    let holder_roster_position = private_row.holder_roster_position;
    if secret_axis_opening.coordinate
        != (MaskedBallotBivariateCommitmentCoordinate320::SecretAxis {
            holder_roster_position,
        })
    {
        return Err(masked_ballot_commitment_object_mismatch(
            "secret-axis coordinate",
        ));
    }
    let evaluation_point =
        canonical_evaluation_point_320(layout.participant_count(), holder_roster_position)?;
    let mut crosspoints = Vec::with_capacity(
        usize::from(layout.participant_count())
            .checked_sub(1)
            .ok_or(MaskedBallotBivariateCommitmentError320::ArithmeticOverflow)?,
    );
    for (peer_roster_position, opening) in (0..layout.participant_count())
        .filter(|position| *position != holder_roster_position)
        .zip(opening_iterator)
    {
        let expected_coordinate = MaskedBallotBivariateCommitmentCoordinate320::Crosspoint {
            lower_holder_roster_position: holder_roster_position.min(peer_roster_position),
            upper_holder_roster_position: holder_roster_position.max(peer_roster_position),
        };
        if opening.coordinate != expected_coordinate {
            return Err(masked_ballot_commitment_object_mismatch(
                "crosspoint coordinate",
            ));
        }
        crosspoints.push(MaskedBallotBivariateCrosspoint320::from_parts(
            peer_roster_position,
            canonical_evaluation_point_320(layout.participant_count(), peer_roster_position)?,
            opening.value,
        ));
    }
    let row = MaskedBallotBivariateRow320::from_parts(
        layout.participant_count(),
        holder_roster_position,
        evaluation_point,
        secret_axis_opening.value,
        crosspoints,
    )?;
    if !row.is_locally_degree_bounded(usize::from(layout.reconstruction_threshold())) {
        return Err(
            MaskedBallotBivariateCommitmentError320::LocalRowDegreeMismatch {
                holder_roster_position,
            },
        );
    }
    Ok(AuthenticatedMaskedBallotBivariatePrivateRow320 {
        root_body_identity: authenticated_root.root_body_identity(),
        author_roster_position: layout.author_roster_position(),
        holder_roster_position,
        row,
    })
}

pub(crate) fn derive_masked_ballot_bivariate_commitment_digest_320(
    layout: MaskedBallotBivariateCommitmentLayout320,
    coordinate: MaskedBallotBivariateCommitmentCoordinate320,
    value: BinaryFieldElement320,
    salt: [u8; MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH],
) -> Result<Hash512, MaskedBallotBivariateCommitmentError320> {
    layout.validate_coordinate(coordinate)?;
    let leaf_ordinal = layout.leaf_ordinal(coordinate)?;
    let mut items = vec![
        CanonicalItem::hash512(layout.identity().into_bytes()),
        CanonicalItem::unsigned64(leaf_ordinal),
        CanonicalItem::unsigned16(layout.participant_count()),
        CanonicalItem::unsigned16(layout.author_roster_position()),
    ];
    coordinate.append_hash_items(&mut items);
    items.push(CanonicalItem::fixed_bytes(value.canonical_bytes())?);
    items.push(CanonicalItem::fixed_bytes(salt)?);
    Ok(hash_foundation_tuple_512(
        MASKED_BALLOT_BIVARIATE_COMMITMENT_DIGEST_DOMAIN,
        &items,
    )?)
}

fn evaluate_commitment_coordinate(
    layout: MaskedBallotBivariateCommitmentLayout320,
    polynomial: &MaskedBallotSymmetricBivariatePolynomial320,
    coordinate: MaskedBallotBivariateCommitmentCoordinate320,
) -> Result<BinaryFieldElement320, MaskedBallotBivariateCommitmentError320> {
    layout.validate_coordinate(coordinate)?;
    match coordinate {
        MaskedBallotBivariateCommitmentCoordinate320::SecretAxis {
            holder_roster_position,
        } => Ok(polynomial.evaluate(
            canonical_evaluation_point_320(layout.participant_count(), holder_roster_position)?,
            BinaryFieldElement320::ZERO,
        )),
        MaskedBallotBivariateCommitmentCoordinate320::Crosspoint {
            lower_holder_roster_position,
            upper_holder_roster_position,
        } => Ok(polynomial.evaluate(
            canonical_evaluation_point_320(
                layout.participant_count(),
                lower_holder_roster_position,
            )?,
            canonical_evaluation_point_320(
                layout.participant_count(),
                upper_holder_roster_position,
            )?,
        )),
    }
}

fn private_row_payload_byte_length(
    participant_count: u16,
) -> Result<usize, MaskedBallotBivariateCommitmentError320> {
    usize::from(participant_count)
        .checked_mul(
            BinaryFieldElement320::CANONICAL_BYTE_LENGTH
                + MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH,
        )
        .ok_or(MaskedBallotBivariateCommitmentError320::ArithmeticOverflow)
}

fn require_object_header(
    tuple: &CanonicalTuple,
    expected_domain: &str,
    expected_item_count: usize,
) -> Result<(), MaskedBallotBivariateCommitmentError320> {
    if tuple.schema_identifier != CANONICAL_TUPLE_SCHEMA_IDENTIFIER
        || tuple.schema_version != CANONICAL_TUPLE_VERSION
        || tuple.items.len() != expected_item_count
    {
        return Err(masked_ballot_commitment_object_mismatch("header"));
    }
    if tuple.items[0].item_type() != CanonicalItemType::Ascii
        || tuple.items[0].variable_value_bytes()? != expected_domain.as_bytes()
    {
        return Err(masked_ballot_commitment_object_mismatch("object domain"));
    }
    Ok(())
}

fn read_hash(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<Hash512, MaskedBallotBivariateCommitmentError320> {
    if item.item_type() != CanonicalItemType::Hash512 {
        return Err(masked_ballot_commitment_object_mismatch(field));
    }
    let bytes: [u8; Hash512::BYTE_LENGTH] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| masked_ballot_commitment_object_mismatch(field))?;
    Ok(Hash512::from_bytes(bytes))
}

fn require_hash(
    item: &CanonicalItem,
    expected: Hash512,
    field: &'static str,
) -> Result<(), MaskedBallotBivariateCommitmentError320> {
    if read_hash(item, field)? != expected {
        return Err(masked_ballot_commitment_object_mismatch(field));
    }
    Ok(())
}

fn read_u16(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u16, MaskedBallotBivariateCommitmentError320> {
    if item.item_type() != CanonicalItemType::Unsigned16 {
        return Err(masked_ballot_commitment_object_mismatch(field));
    }
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| masked_ballot_commitment_object_mismatch(field))?;
    Ok(u16::from_le_bytes(bytes))
}

fn require_u16(
    item: &CanonicalItem,
    expected: u16,
    field: &'static str,
) -> Result<(), MaskedBallotBivariateCommitmentError320> {
    if read_u16(item, field)? != expected {
        return Err(masked_ballot_commitment_object_mismatch(field));
    }
    Ok(())
}

fn read_u64(
    item: &CanonicalItem,
    field: &'static str,
) -> Result<u64, MaskedBallotBivariateCommitmentError320> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(masked_ballot_commitment_object_mismatch(field));
    }
    let bytes: [u8; 8] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| masked_ballot_commitment_object_mismatch(field))?;
    Ok(u64::from_le_bytes(bytes))
}

fn require_u64(
    item: &CanonicalItem,
    expected: u64,
    field: &'static str,
) -> Result<(), MaskedBallotBivariateCommitmentError320> {
    if read_u64(item, field)? != expected {
        return Err(masked_ballot_commitment_object_mismatch(field));
    }
    Ok(())
}

const fn masked_ballot_commitment_object_mismatch(
    field: &'static str,
) -> MaskedBallotBivariateCommitmentError320 {
    MaskedBallotBivariateCommitmentError320::ObjectMismatch { field }
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
        maximum_cumulative_work_byte_length: 16 * 1024,
        maximum_cumulative_allocation_byte_length: 16 * 1024,
    }
}

fn private_row_body_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_tuple_byte_length: MAXIMUM_PRIVATE_ROW_BODY_BYTE_LENGTH,
        maximum_item_count: PRIVATE_ROW_BODY_ITEM_COUNT,
        maximum_item_byte_length: MAXIMUM_PRIVATE_ROW_BODY_ITEM_BYTE_LENGTH,
        maximum_nesting_depth: 1,
        maximum_cumulative_work_byte_length: 32 * 1024,
        maximum_cumulative_allocation_byte_length: 32 * 1024,
    }
}

const _: () = assert!(ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH == ml_dsa_65::PK_LEN);
const _: () = assert!(MASKED_BALLOT_ML_DSA_65_SIGNATURE_BYTE_LENGTH == ml_dsa_65::SIG_LEN);
