use crate::bgv::proof_suite::common_proof_randomness_purpose_is_assigned;

use super::super::schemas::SchemaResult;
use super::super::{FoundationSchemaError, RefusalReason};
use super::{
    ORDINARY_BALLOT_PROOF_FAMILY, PUBLIC_ONLY_PROOF_FAMILIES, RESET_SAFE_PROOF_FAMILIES,
    SETUP_MAILBOX_FAMILY, SETUP_SOURCE_FAMILY, SUITE_DISTRIBUTION_FAMILY, TARGET_FLOODING_FAMILY,
    VSS_EXPANSION_FAMILY, schema_error,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AttemptClass {
    ResetSafeSetup,
    BallotEncryption,
    ResetSafeProof,
    OrdinaryProof,
    TargetRelease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateRandomnessDomain {
    pub(super) family: u16,
    pub(super) purpose: u16,
}

impl PrivateRandomnessDomain {
    pub fn setup_suite_distribution(purpose: u16) -> SchemaResult<Self> {
        if !matches!(purpose, 1..=7 | 11 | 12) {
            return Err(unassigned_randomness_domain());
        }
        Ok(Self {
            family: SUITE_DISTRIBUTION_FAMILY,
            purpose,
        })
    }

    pub fn ballot_encryption_distribution(purpose: u16) -> SchemaResult<Self> {
        if !matches!(purpose, 8..=10) {
            return Err(unassigned_randomness_domain());
        }
        Ok(Self {
            family: SUITE_DISTRIBUTION_FAMILY,
            purpose,
        })
    }

    pub fn setup_source(purpose: u16) -> SchemaResult<Self> {
        if !matches!(purpose, 1 | 2 | 4) {
            return Err(unassigned_randomness_domain());
        }
        Ok(Self {
            family: SETUP_SOURCE_FAMILY,
            purpose,
        })
    }

    pub fn setup_mailbox(purpose: u16) -> SchemaResult<Self> {
        assigned_fixed_purpose_domain(SETUP_MAILBOX_FAMILY, purpose, 3)
    }

    pub fn vss_expansion(purpose: u16) -> SchemaResult<Self> {
        assigned_fixed_purpose_domain(VSS_EXPANSION_FAMILY, purpose, 4)
    }

    pub fn target_flooding(purpose: u16) -> SchemaResult<Self> {
        if !(1..=2).contains(&purpose) {
            return Err(unassigned_randomness_domain());
        }
        Ok(Self {
            family: TARGET_FLOODING_FAMILY,
            purpose,
        })
    }

    pub fn reset_safe_proof(statement_schema_identifier: u16, purpose: u16) -> SchemaResult<Self> {
        proof_domain(
            statement_schema_identifier,
            purpose,
            AttemptClass::ResetSafeProof,
        )
    }

    pub fn ordinary_proof(purpose: u16) -> SchemaResult<Self> {
        proof_domain(
            ORDINARY_BALLOT_PROOF_FAMILY,
            purpose,
            AttemptClass::OrdinaryProof,
        )
    }

    pub(crate) fn from_assigned_pair(family: u16, purpose: u16) -> SchemaResult<Self> {
        match family {
            SUITE_DISTRIBUTION_FAMILY if matches!(purpose, 1..=7 | 11 | 12) => {
                Self::setup_suite_distribution(purpose)
            }
            SUITE_DISTRIBUTION_FAMILY if matches!(purpose, 8..=10) => {
                Self::ballot_encryption_distribution(purpose)
            }
            SETUP_SOURCE_FAMILY => Self::setup_source(purpose),
            SETUP_MAILBOX_FAMILY => Self::setup_mailbox(purpose),
            VSS_EXPANSION_FAMILY => Self::vss_expansion(purpose),
            TARGET_FLOODING_FAMILY => Self::target_flooding(purpose),
            ORDINARY_BALLOT_PROOF_FAMILY => Self::ordinary_proof(purpose),
            family
                if RESET_SAFE_PROOF_FAMILIES.contains(&family)
                    || PUBLIC_ONLY_PROOF_FAMILIES.contains(&family) =>
            {
                Self::reset_safe_proof(family, purpose)
            }
            _ => Err(unassigned_randomness_domain()),
        }
    }

    pub const fn family(self) -> u16 {
        self.family
    }

    pub const fn purpose(self) -> u16 {
        self.purpose
    }

    pub(super) fn attempt_class(self) -> AttemptClass {
        match self.family {
            SUITE_DISTRIBUTION_FAMILY if matches!(self.purpose, 8..=10) => {
                AttemptClass::BallotEncryption
            }
            SUITE_DISTRIBUTION_FAMILY
            | SETUP_SOURCE_FAMILY
            | SETUP_MAILBOX_FAMILY
            | VSS_EXPANSION_FAMILY => AttemptClass::ResetSafeSetup,
            TARGET_FLOODING_FAMILY => AttemptClass::TargetRelease,
            ORDINARY_BALLOT_PROOF_FAMILY => AttemptClass::OrdinaryProof,
            _ => AttemptClass::ResetSafeProof,
        }
    }
}

fn assigned_fixed_purpose_domain(
    family: u16,
    purpose: u16,
    maximum_purpose: u16,
) -> SchemaResult<PrivateRandomnessDomain> {
    if purpose == 0 || purpose > maximum_purpose {
        return Err(unassigned_randomness_domain());
    }
    Ok(PrivateRandomnessDomain { family, purpose })
}

fn proof_domain(
    statement_schema_identifier: u16,
    purpose: u16,
    attempt_class: AttemptClass,
) -> SchemaResult<PrivateRandomnessDomain> {
    if purpose == 0 || purpose == u16::MAX {
        return Err(unassigned_randomness_domain());
    }
    let family_matches_attempt = match attempt_class {
        AttemptClass::ResetSafeProof => {
            RESET_SAFE_PROOF_FAMILIES.contains(&statement_schema_identifier)
                || PUBLIC_ONLY_PROOF_FAMILIES.contains(&statement_schema_identifier)
        }
        AttemptClass::OrdinaryProof => statement_schema_identifier == ORDINARY_BALLOT_PROOF_FAMILY,
        AttemptClass::ResetSafeSetup
        | AttemptClass::BallotEncryption
        | AttemptClass::TargetRelease => false,
    };
    if !family_matches_attempt
        || !common_proof_randomness_purpose_is_assigned(statement_schema_identifier, purpose)
    {
        return Err(unassigned_randomness_domain());
    }
    Ok(PrivateRandomnessDomain {
        family: statement_schema_identifier,
        purpose,
    })
}

fn unassigned_randomness_domain() -> FoundationSchemaError {
    schema_error(
        RefusalReason::WrongTypeOrLength,
        "private-randomness family and purpose pair is not assigned",
    )
}
