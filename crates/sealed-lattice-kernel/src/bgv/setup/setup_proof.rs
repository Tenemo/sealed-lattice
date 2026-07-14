pub(in crate::bgv::setup) mod material_transport;

pub(crate) use self::material_transport::{
    BgvProofMaterialBytes, CanonicalProofMaterialBytes, ProofByteSource,
};
pub(in crate::bgv::setup) use self::material_transport::{
    SetupProofMaterialBytes, take_verified_setup_proof_material_bytes,
};
#[cfg(test)]
pub(in crate::bgv::setup) use self::material_transport::{
    authenticate_setup_proof_material_stream_for_test,
    authenticate_setup_proof_material_stream_in_session_for_test,
};

use serde_json::json;

use crate::{
    bgv::setup_helpers::validate_hash_string,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::CanonicalStreamDomain,
    hashing::derive_canonical_object_hash,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::setup) enum SetupProofFamily {
    PrivateVssShare,
    VssShareLinkage,
    SameSecretBridge,
    PublicKeyShare,
    TrusteeEvaluationKey,
    TargetDecryptionShare,
    TargetDecryptionAggregateOpening,
}

impl SetupProofFamily {
    pub(in crate::bgv::setup) const fn wire_label(self) -> &'static str {
        match self {
            Self::PrivateVssShare => "vss-opening-carry",
            Self::VssShareLinkage => "vss-share-linkage",
            Self::SameSecretBridge => "same-secret-bridge",
            Self::PublicKeyShare => "public-key-share",
            Self::TrusteeEvaluationKey => "trustee-evaluation-key",
            Self::TargetDecryptionShare => "target-decryption-share",
            Self::TargetDecryptionAggregateOpening => "target-decryption-aggregate-opening",
        }
    }

    pub(in crate::bgv::setup) fn from_wire_label(wire_label: &str) -> Option<Self> {
        match wire_label {
            "vss-opening-carry" => Some(Self::PrivateVssShare),
            "vss-share-linkage" => Some(Self::VssShareLinkage),
            "same-secret-bridge" => Some(Self::SameSecretBridge),
            "public-key-share" => Some(Self::PublicKeyShare),
            "trustee-evaluation-key" => Some(Self::TrusteeEvaluationKey),
            "target-decryption-share" => Some(Self::TargetDecryptionShare),
            "target-decryption-aggregate-opening" => Some(Self::TargetDecryptionAggregateOpening),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(in crate::bgv::setup) const fn stream_code(self) -> u32 {
        match self {
            Self::PrivateVssShare => 1,
            Self::VssShareLinkage => 2,
            Self::SameSecretBridge => 3,
            Self::PublicKeyShare => 4,
            Self::TrusteeEvaluationKey => 5,
            Self::TargetDecryptionShare => 8,
            Self::TargetDecryptionAggregateOpening => 11,
        }
    }

    pub(in crate::bgv::setup) fn from_stream_code(stream_code: u32) -> Option<Self> {
        match stream_code {
            1 => Some(Self::PrivateVssShare),
            2 => Some(Self::VssShareLinkage),
            3 => Some(Self::SameSecretBridge),
            4 => Some(Self::PublicKeyShare),
            5 => Some(Self::TrusteeEvaluationKey),
            8 => Some(Self::TargetDecryptionShare),
            11 => Some(Self::TargetDecryptionAggregateOpening),
            _ => None,
        }
    }

    pub(in crate::bgv::setup) const fn stream_domain(self) -> CanonicalStreamDomain {
        match self {
            Self::PrivateVssShare | Self::VssShareLinkage => {
                CanonicalStreamDomain::DealerVssShareLinkageProof
            }
            Self::SameSecretBridge => CanonicalStreamDomain::SameSecretProof,
            Self::PublicKeyShare => CanonicalStreamDomain::PublicKeyShareProof,
            Self::TrusteeEvaluationKey => CanonicalStreamDomain::EvaluatorKeyAggregateProof,
            Self::TargetDecryptionShare => CanonicalStreamDomain::MaliciousTargetShareProof,
            Self::TargetDecryptionAggregateOpening => {
                CanonicalStreamDomain::RecipientAggregateThresholdShareProof
            }
        }
    }

    pub(in crate::bgv::setup) const fn proof_bytes_hash_domain(self) -> Option<&'static str> {
        match self {
            Self::PrivateVssShare => {
                Some("sealed-lattice/setup/private-vss-share/succinct-proof-bytes")
            }
            Self::VssShareLinkage => Some("sealed-lattice/setup/vss-share-linkage/proof-bytes"),
            Self::SameSecretBridge => Some("sealed-lattice/setup/same-secret-bridge/proof-bytes"),
            Self::PublicKeyShare => {
                Some("sealed-lattice/setup/public-key-share/succinct-proof-bytes")
            }
            Self::TrusteeEvaluationKey => {
                Some("sealed-lattice/setup/trustee-evaluation-key/proof-bytes")
            }
            Self::TargetDecryptionShare => {
                Some("sealed-lattice/target-decryption/share-proof/proof-bytes")
            }
            Self::TargetDecryptionAggregateOpening => None,
        }
    }

    pub(in crate::bgv::setup) const fn binding_labels(self) -> &'static [&'static str] {
        match self {
            Self::PublicKeyShare => &[
                "sameSecretBridgeStatementRoot",
                "sameSecretBridgeProofRecordRoot",
            ],
            Self::PrivateVssShare => &[
                "sourceTrusteeCommitmentRoot",
                "privateEnvelopeAadHash",
                "shareValuesHash",
            ],
            Self::VssShareLinkage => &["shareLinkageStatementRoot"],
            Self::SameSecretBridge | Self::TargetDecryptionAggregateOpening => &[],
            Self::TargetDecryptionShare => &[
                "targetShareProofStatementRoot",
                "activeCredentialBindingRoot",
                "smudgingCommitmentSetRoot",
            ],
            Self::TrusteeEvaluationKey => &[
                "evaluatorKeyScheduleRoot",
                "sourceConstantCoefficientCommitmentRoot",
            ],
        }
    }
}

fn setup_proof_error(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::ComponentMismatch, message)
}

pub(in crate::bgv::setup) fn setup_proof_material_reference_root(
    proof_family: &str,
    proof_bytes_hash: &str,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "SetupProofMaterialReference",
        "proofFamily": proof_family,
        "proofBytesHash": proof_bytes_hash,
    }))
}
