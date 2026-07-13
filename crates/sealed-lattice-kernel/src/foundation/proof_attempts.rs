/// The complete proof-family set admitted by the version-one foundation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ProofFamily {
    SourceBatchedVerifiableSecretSharingLinkage = 0x2110,
    AggregateThresholdShare = 0x2111,
    SameSecretLinkage = 0x1211,
    PublicKeyShare = 0x1212,
    CollectivePublicKeyAggregate = 0x1213,
    RelinearizationRoundOne = 0x1214,
    RelinearizationRoundOneAggregate = 0x1215,
    RelinearizationRoundTwo = 0x1216,
    GaloisKeyShare = 0x1217,
    EvaluatorKeyAggregate = 0x1218,
    BallotValidity = 0x1302,
    PairedTargetShare = 0x1621,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofPrivateCoinClassification {
    PublicOnly,
    ResetSafeSecretBearing,
    OrdinarySecretBearing,
}

impl ProofFamily {
    pub const ALL: [Self; 12] = [
        Self::SourceBatchedVerifiableSecretSharingLinkage,
        Self::AggregateThresholdShare,
        Self::SameSecretLinkage,
        Self::PublicKeyShare,
        Self::CollectivePublicKeyAggregate,
        Self::RelinearizationRoundOne,
        Self::RelinearizationRoundOneAggregate,
        Self::RelinearizationRoundTwo,
        Self::GaloisKeyShare,
        Self::EvaluatorKeyAggregate,
        Self::BallotValidity,
        Self::PairedTargetShare,
    ];

    pub const fn statement_schema_identifier(self) -> u16 {
        self as u16
    }

    pub const fn from_statement_schema_identifier(identifier: u16) -> Option<Self> {
        match identifier {
            0x2110 => Some(Self::SourceBatchedVerifiableSecretSharingLinkage),
            0x2111 => Some(Self::AggregateThresholdShare),
            0x1211 => Some(Self::SameSecretLinkage),
            0x1212 => Some(Self::PublicKeyShare),
            0x1213 => Some(Self::CollectivePublicKeyAggregate),
            0x1214 => Some(Self::RelinearizationRoundOne),
            0x1215 => Some(Self::RelinearizationRoundOneAggregate),
            0x1216 => Some(Self::RelinearizationRoundTwo),
            0x1217 => Some(Self::GaloisKeyShare),
            0x1218 => Some(Self::EvaluatorKeyAggregate),
            0x1302 => Some(Self::BallotValidity),
            0x1621 => Some(Self::PairedTargetShare),
            _ => None,
        }
    }

    pub const fn private_coin_classification(self) -> ProofPrivateCoinClassification {
        match self {
            Self::CollectivePublicKeyAggregate
            | Self::RelinearizationRoundOneAggregate
            | Self::EvaluatorKeyAggregate => ProofPrivateCoinClassification::PublicOnly,
            Self::BallotValidity => ProofPrivateCoinClassification::OrdinarySecretBearing,
            Self::SourceBatchedVerifiableSecretSharingLinkage
            | Self::AggregateThresholdShare
            | Self::SameSecretLinkage
            | Self::PublicKeyShare
            | Self::RelinearizationRoundOne
            | Self::RelinearizationRoundTwo
            | Self::GaloisKeyShare
            | Self::PairedTargetShare => ProofPrivateCoinClassification::ResetSafeSecretBearing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigned_family_codes_round_trip() {
        for family in ProofFamily::ALL {
            assert_eq!(
                ProofFamily::from_statement_schema_identifier(family.statement_schema_identifier()),
                Some(family)
            );
        }
        assert_eq!(ProofFamily::from_statement_schema_identifier(0), None);
    }

    #[test]
    fn private_coin_classification_is_closed_for_every_family() {
        let public_only_count = ProofFamily::ALL
            .iter()
            .filter(|family| {
                family.private_coin_classification() == ProofPrivateCoinClassification::PublicOnly
            })
            .count();
        let reset_safe_count = ProofFamily::ALL
            .iter()
            .filter(|family| {
                family.private_coin_classification()
                    == ProofPrivateCoinClassification::ResetSafeSecretBearing
            })
            .count();
        let ordinary_count = ProofFamily::ALL
            .iter()
            .filter(|family| {
                family.private_coin_classification()
                    == ProofPrivateCoinClassification::OrdinarySecretBearing
            })
            .count();
        assert_eq!(
            (public_only_count, reset_safe_count, ordinary_count),
            (3, 8, 1)
        );
    }
}
