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
}
