use core::fmt;

use crate::foundation::{
    ActionContext, CanonicalCodecError, CanonicalItem, FOUNDATION_PROFILE, Hash512, Roster,
    derive_foundation_roster_parameters, hash_foundation_tuple_512,
};

use super::{
    LocallyJoinedPseudorandomZeroSharingSeedMasters320, TallyPreparationContext,
    TallyPreparationError,
    direct_mpc_candidate_compiler::DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH,
    direct_mpc_field_stream::{
        DIRECT_MPC_FIELD_STREAM_CUSTOMIZATION, DIRECT_MPC_FIELD_STREAM_QUERY_BYTE_LENGTH,
        DIRECT_MPC_SUBSET_MASTER_BYTE_LENGTH, DirectMpcFieldStreamKind,
    },
    direct_mpc_prime_field::DIRECT_MPC_PRIME_FIELD_MODULUS,
    pseudorandom_zero_sharing_seed_catalog_root_terminal_320::PseudorandomZeroSharingSeedCatalogRootTerminalError320,
    pseudorandom_zero_sharing_seed_receipt_320::PseudorandomZeroSharingSeedReceiptError320,
    pseudorandom_zero_sharing_seed_receipt_terminal_320::{
        PseudorandomZeroSharingSeedReceiptTerminalError320,
        RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320,
    },
    replicated_random_sharing::ReplicatedRandomSharingGeometry,
};

const DIRECT_MPC_ONE_AND_SOURCE_PARAMETER_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preprocessing-source-parameter-identity";
const DIRECT_MPC_ONE_AND_SOURCE_TERMINAL_IDENTITY_DOMAIN: &str =
    "sealed-lattice/v1/direct-mpc-one-and/preprocessing-source-terminal-identity";
const PREPARATION_ATTEMPT_ORDINAL: u16 = 0;
const ORDINARY_SHARING_COUNT: u64 = 3;
const DEGREE_SIX_ZERO_SHARING_COUNT: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectMpcOneAndPreprocessingSourceError {
    Canonical(CanonicalCodecError),
    Preparation(TallyPreparationError),
    RootTerminal(PseudorandomZeroSharingSeedCatalogRootTerminalError320),
    Receipt(PseudorandomZeroSharingSeedReceiptError320),
    ReceiptTerminal(PseudorandomZeroSharingSeedReceiptTerminalError320),
    MasterCustody(
        super::pseudorandom_zero_sharing_seed_master_custody_320::PseudorandomZeroSharingSeedMasterCustodyError320,
    ),
    WrongContext,
    WrongSourceParameter,
    WrongLocalCustody,
    ArithmeticOverflow,
}

impl fmt::Display for DirectMpcOneAndPreprocessingSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for DirectMpcOneAndPreprocessingSourceError {}

impl From<CanonicalCodecError> for DirectMpcOneAndPreprocessingSourceError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::Canonical(error)
    }
}

impl From<TallyPreparationError> for DirectMpcOneAndPreprocessingSourceError {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl From<PseudorandomZeroSharingSeedCatalogRootTerminalError320>
    for DirectMpcOneAndPreprocessingSourceError
{
    fn from(error: PseudorandomZeroSharingSeedCatalogRootTerminalError320) -> Self {
        Self::RootTerminal(error)
    }
}

impl From<PseudorandomZeroSharingSeedReceiptError320> for DirectMpcOneAndPreprocessingSourceError {
    fn from(error: PseudorandomZeroSharingSeedReceiptError320) -> Self {
        Self::Receipt(error)
    }
}

impl From<PseudorandomZeroSharingSeedReceiptTerminalError320>
    for DirectMpcOneAndPreprocessingSourceError
{
    fn from(error: PseudorandomZeroSharingSeedReceiptTerminalError320) -> Self {
        Self::ReceiptTerminal(error)
    }
}

impl From<
    super::pseudorandom_zero_sharing_seed_master_custody_320::PseudorandomZeroSharingSeedMasterCustodyError320,
> for DirectMpcOneAndPreprocessingSourceError
{
    fn from(
        error: super::pseudorandom_zero_sharing_seed_master_custody_320::PseudorandomZeroSharingSeedMasterCustodyError320,
    ) -> Self {
        Self::MasterCustody(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectMpcOneAndRecipientReceiptBinding {
    authenticated_inventory_identity: Hash512,
    receipt_body_identity: Hash512,
    receipt_envelope_identity: Hash512,
}

/// Positive success-path verification for the exact subset-seeded one-AND
/// source bytes.
///
/// Construction consumes the already positive root and receipt-terminal
/// results. Those typed results retain state-authorized roots, signed
/// encrypted-delivery inventory commitments, recipient receipts, and
/// all-roster terminal endorsements from their canonical byte verifiers. A
/// participant's local joined custody must also match its public receipt by
/// identity. The receipt terminal does not yet establish durable endorsement
/// locking or a globally consistent burn, so this result remains conditional
/// candidate evidence rather than preparation-continuation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedDirectMpcOneAndPreprocessingSource {
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    root_terminal_identity: Hash512,
    root_terminal_certificate_identity: Hash512,
    receipt_terminal_identity: Hash512,
    receipt_terminal_certificate_identity: Hash512,
    terminal_identity: Hash512,
    receipt_bindings: Box<[DirectMpcOneAndRecipientReceiptBinding]>,
}

impl VerifiedDirectMpcOneAndPreprocessingSource {
    pub(crate) const fn parameter_identity(&self) -> Hash512 {
        self.parameter_identity
    }

    pub(crate) const fn preparation_context(&self) -> TallyPreparationContext {
        self.preparation_context
    }

    pub(crate) const fn root_terminal_identity(&self) -> Hash512 {
        self.root_terminal_identity
    }

    pub(crate) const fn receipt_terminal_identity(&self) -> Hash512 {
        self.receipt_terminal_identity
    }

    pub(crate) const fn receipt_terminal_certificate_identity(&self) -> Hash512 {
        self.receipt_terminal_certificate_identity
    }

    pub(crate) const fn identity(&self) -> Hash512 {
        self.terminal_identity
    }

    pub(crate) fn verify_action_and_roster(
        &self,
        action_context: &ActionContext,
        roster: &Roster,
    ) -> Result<(), DirectMpcOneAndPreprocessingSourceError> {
        roster
            .validate()
            .map_err(|_| DirectMpcOneAndPreprocessingSourceError::WrongContext)?;
        let roster_identity = roster
            .roster_hash()
            .map_err(|_| DirectMpcOneAndPreprocessingSourceError::WrongContext)?;
        if action_context.roster_hash() != roster_identity
            || self.preparation_context.action_context_hash() != action_context.context_hash()
            || self.preparation_context.roster_hash() != roster_identity
        {
            return Err(DirectMpcOneAndPreprocessingSourceError::WrongContext);
        }
        Ok(())
    }

    pub(crate) fn verify_action_roster_and_local_custody(
        &self,
        action_context: &ActionContext,
        roster: &Roster,
        joined_seed_masters: &LocallyJoinedPseudorandomZeroSharingSeedMasters320,
    ) -> Result<(), DirectMpcOneAndPreprocessingSourceError> {
        self.verify_action_and_roster(action_context, roster)?;
        self.verify_local_custody(joined_seed_masters)
    }

    pub(crate) fn verify_local_custody(
        &self,
        joined_seed_masters: &LocallyJoinedPseudorandomZeroSharingSeedMasters320,
    ) -> Result<(), DirectMpcOneAndPreprocessingSourceError> {
        if joined_seed_masters.parameter_identity() != self.parameter_identity
            || joined_seed_masters.preparation_context() != self.preparation_context
            || joined_seed_masters.root_terminal_identity() != self.root_terminal_identity
            || joined_seed_masters.root_terminal_certificate_identity()
                != self.root_terminal_certificate_identity
            || joined_seed_masters.receipt_terminal_identity() != self.receipt_terminal_identity
            || joined_seed_masters.receipt_terminal_certificate_identity()
                != self.receipt_terminal_certificate_identity
        {
            return Err(DirectMpcOneAndPreprocessingSourceError::WrongLocalCustody);
        }
        let receipt_binding = self
            .receipt_bindings
            .get(usize::from(joined_seed_masters.participant_position()))
            .ok_or(DirectMpcOneAndPreprocessingSourceError::WrongLocalCustody)?;
        if joined_seed_masters.authenticated_recipient_inventory_identity()
            != receipt_binding.authenticated_inventory_identity
            || joined_seed_masters.receipt_body_identity() != receipt_binding.receipt_body_identity
            || joined_seed_masters.receipt_envelope_identity()
                != receipt_binding.receipt_envelope_identity
        {
            return Err(DirectMpcOneAndPreprocessingSourceError::WrongLocalCustody);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn from_joined_custody_for_test(
        action_context: &ActionContext,
        roster: &Roster,
        joined_seed_masters: &LocallyJoinedPseudorandomZeroSharingSeedMasters320,
    ) -> Result<Self, DirectMpcOneAndPreprocessingSourceError> {
        let parameter_identity = direct_mpc_one_and_preprocessing_source_parameter_identity()?;
        if joined_seed_masters.parameter_identity() != parameter_identity {
            return Err(DirectMpcOneAndPreprocessingSourceError::WrongSourceParameter);
        }
        let binding = DirectMpcOneAndRecipientReceiptBinding {
            authenticated_inventory_identity: joined_seed_masters
                .authenticated_recipient_inventory_identity(),
            receipt_body_identity: joined_seed_masters.receipt_body_identity(),
            receipt_envelope_identity: joined_seed_masters.receipt_envelope_identity(),
        };
        let terminal_identity = source_terminal_identity(
            parameter_identity,
            joined_seed_masters.preparation_context(),
            joined_seed_masters.root_terminal_identity(),
            joined_seed_masters.root_terminal_certificate_identity(),
            joined_seed_masters.receipt_terminal_identity(),
            joined_seed_masters.receipt_terminal_certificate_identity(),
        )?;
        let source = Self {
            parameter_identity,
            preparation_context: joined_seed_masters.preparation_context(),
            root_terminal_identity: joined_seed_masters.root_terminal_identity(),
            root_terminal_certificate_identity: joined_seed_masters
                .root_terminal_certificate_identity(),
            receipt_terminal_identity: joined_seed_masters.receipt_terminal_identity(),
            receipt_terminal_certificate_identity: joined_seed_masters
                .receipt_terminal_certificate_identity(),
            terminal_identity,
            receipt_bindings: vec![binding; usize::from(FOUNDATION_PROFILE.participant_count)]
                .into_boxed_slice(),
        };
        source.verify_action_roster_and_local_custody(
            action_context,
            roster,
            joined_seed_masters,
        )?;
        Ok(source)
    }
}

pub(crate) fn direct_mpc_one_and_preprocessing_source_parameter_identity()
-> Result<Hash512, DirectMpcOneAndPreprocessingSourceError> {
    let roster_parameters =
        derive_foundation_roster_parameters(FOUNDATION_PROFILE.participant_count)
            .ok_or(DirectMpcOneAndPreprocessingSourceError::WrongContext)?;
    let sharing_geometry =
        ReplicatedRandomSharingGeometry::derive(FOUNDATION_PROFILE.participant_count)?;
    let degree_six = roster_parameters
        .active_fault_bound
        .checked_mul(2)
        .ok_or(DirectMpcOneAndPreprocessingSourceError::ArithmeticOverflow)?;
    Ok(hash_foundation_tuple_512(
        DIRECT_MPC_ONE_AND_SOURCE_PARAMETER_IDENTITY_DOMAIN,
        &[
            CanonicalItem::unsigned16(PREPARATION_ATTEMPT_ORDINAL),
            CanonicalItem::unsigned16(FOUNDATION_PROFILE.participant_count),
            CanonicalItem::unsigned16(roster_parameters.active_fault_bound),
            CanonicalItem::unsigned16(roster_parameters.reconstruction_threshold),
            CanonicalItem::unsigned64(sharing_geometry.authorized_subset_size),
            CanonicalItem::unsigned64(sharing_geometry.authorized_subset_count),
            CanonicalItem::unsigned64(sharing_geometry.authorized_subset_count_per_participant),
            CanonicalItem::unsigned32(DIRECT_MPC_PRIME_FIELD_MODULUS),
            CanonicalItem::unsigned64(DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH),
            CanonicalItem::unsigned16(
                u16::try_from(DIRECT_MPC_SUBSET_MASTER_BYTE_LENGTH)
                    .map_err(|_| DirectMpcOneAndPreprocessingSourceError::ArithmeticOverflow)?,
            ),
            CanonicalItem::unsigned16(
                u16::try_from(DIRECT_MPC_FIELD_STREAM_QUERY_BYTE_LENGTH)
                    .map_err(|_| DirectMpcOneAndPreprocessingSourceError::ArithmeticOverflow)?,
            ),
            CanonicalItem::variable_bytes(DIRECT_MPC_FIELD_STREAM_CUSTOMIZATION)?,
            CanonicalItem::unsigned16(DirectMpcFieldStreamKind::OrdinaryDegreeThree as u16),
            CanonicalItem::unsigned16(roster_parameters.active_fault_bound),
            CanonicalItem::unsigned16(1),
            CanonicalItem::unsigned64(ORDINARY_SHARING_COUNT),
            CanonicalItem::unsigned16(DirectMpcFieldStreamKind::DegreeSixZeroBasis as u16),
            CanonicalItem::unsigned16(degree_six),
            CanonicalItem::unsigned16(roster_parameters.active_fault_bound),
            CanonicalItem::unsigned64(DEGREE_SIX_ZERO_SHARING_COUNT),
        ],
    )?)
}

pub(crate) fn verify_direct_mpc_one_and_preprocessing_source(
    roster: &Roster,
    receipt_terminal: &RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320,
) -> Result<VerifiedDirectMpcOneAndPreprocessingSource, DirectMpcOneAndPreprocessingSourceError> {
    roster
        .validate()
        .map_err(|_| DirectMpcOneAndPreprocessingSourceError::WrongContext)?;
    let roster_identity = roster
        .roster_hash()
        .map_err(|_| DirectMpcOneAndPreprocessingSourceError::WrongContext)?;
    let root_terminal = receipt_terminal.root_terminal();
    let root_inventory = root_terminal.root_inventory();
    let root_inventory_body = root_inventory.body();
    let parameter_identity = direct_mpc_one_and_preprocessing_source_parameter_identity()?;
    if root_inventory_body.parameter_identity() != parameter_identity
        || root_inventory_body.participant_count() != FOUNDATION_PROFILE.participant_count
    {
        return Err(DirectMpcOneAndPreprocessingSourceError::WrongSourceParameter);
    }
    let preparation_context = root_inventory
        .root_body(0)
        .ok_or(DirectMpcOneAndPreprocessingSourceError::WrongContext)?
        .layout()
        .preparation_context();
    if preparation_context.identity() != root_inventory_body.preparation_context_identity()
        || preparation_context.roster_hash() != roster_identity
        || preparation_context.participant_count() != FOUNDATION_PROFILE.participant_count
        || receipt_terminal.receipt_inventory().receipts().len()
            != usize::from(FOUNDATION_PROFILE.participant_count)
    {
        return Err(DirectMpcOneAndPreprocessingSourceError::WrongContext);
    }
    let receipt_bindings = receipt_terminal
        .receipt_inventory()
        .receipts()
        .iter()
        .enumerate()
        .map(|(expected_position, receipt)| {
            let receipt_body = receipt.receipt_body();
            if usize::from(receipt_body.recipient_position()) != expected_position
                || receipt_body.parameter_identity() != parameter_identity
                || receipt_body.preparation_context_identity() != preparation_context.identity()
                || receipt_body.root_terminal_identity() != root_terminal.identity()?
                || receipt_body.participant_count() != FOUNDATION_PROFILE.participant_count
            {
                return Err(DirectMpcOneAndPreprocessingSourceError::WrongContext);
            }
            Ok(DirectMpcOneAndRecipientReceiptBinding {
                authenticated_inventory_identity: receipt_body
                    .authenticated_recipient_inventory_identity(),
                receipt_body_identity: receipt_body.identity()?,
                receipt_envelope_identity: receipt.receipt_envelope_identity(),
            })
        })
        .collect::<Result<Vec<_>, DirectMpcOneAndPreprocessingSourceError>>()?
        .into_boxed_slice();
    let root_terminal_identity = root_terminal.identity()?;
    let root_terminal_certificate_identity = root_terminal.certificate_identity();
    let receipt_terminal_identity = receipt_terminal.identity()?;
    let receipt_terminal_certificate_identity = receipt_terminal.certificate_identity();
    let terminal_identity = source_terminal_identity(
        parameter_identity,
        preparation_context,
        root_terminal_identity,
        root_terminal_certificate_identity,
        receipt_terminal_identity,
        receipt_terminal_certificate_identity,
    )?;
    Ok(VerifiedDirectMpcOneAndPreprocessingSource {
        parameter_identity,
        preparation_context,
        root_terminal_identity,
        root_terminal_certificate_identity,
        receipt_terminal_identity,
        receipt_terminal_certificate_identity,
        terminal_identity,
        receipt_bindings,
    })
}

/// Positively reconstructs the exact public source and verifies its local
/// participant custody from one authenticated joined record. The local masters
/// are dropped before this function returns; only the public source result and
/// the verified participant coordinate survive.
pub(crate) fn verify_direct_mpc_one_and_preprocessing_source_from_joined_custody(
    action_context: &ActionContext,
    expected_roster: &Roster,
    joined_custody_record_bytes: &[u8],
) -> Result<
    (VerifiedDirectMpcOneAndPreprocessingSource, u16),
    DirectMpcOneAndPreprocessingSourceError,
> {
    let (joined_seed_masters, receipt_terminal, roster) =
        super::pseudorandom_zero_sharing_seed_master_custody_320::restore_pseudorandom_zero_sharing_joined_seed_masters_and_public_source_320(
            joined_custody_record_bytes,
        )?;
    if roster != *expected_roster {
        return Err(DirectMpcOneAndPreprocessingSourceError::WrongContext);
    }
    let source = verify_direct_mpc_one_and_preprocessing_source(&roster, &receipt_terminal)?;
    source.verify_action_roster_and_local_custody(action_context, &roster, &joined_seed_masters)?;
    Ok((source, joined_seed_masters.participant_position()))
}

fn source_terminal_identity(
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    root_terminal_identity: Hash512,
    root_terminal_certificate_identity: Hash512,
    receipt_terminal_identity: Hash512,
    receipt_terminal_certificate_identity: Hash512,
) -> Result<Hash512, DirectMpcOneAndPreprocessingSourceError> {
    Ok(hash_foundation_tuple_512(
        DIRECT_MPC_ONE_AND_SOURCE_TERMINAL_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(parameter_identity.into_bytes()),
            CanonicalItem::hash512(preparation_context.identity().into_bytes()),
            CanonicalItem::hash512(root_terminal_identity.into_bytes()),
            CanonicalItem::hash512(root_terminal_certificate_identity.into_bytes()),
            CanonicalItem::hash512(receipt_terminal_identity.into_bytes()),
            CanonicalItem::hash512(receipt_terminal_certificate_identity.into_bytes()),
        ],
    )?)
}
