use std::sync::OnceLock;

use crate::{
    foundation::{PRIVATE_PROOF_SALT_PURPOSE, ProofApplicationSlotCeilings},
    hashing::hash_framed_parts_512 as hash512,
};

const PROOF_TRANSCRIPT_DOMAIN_HASH_DOMAIN: &str =
    "sealed-lattice/proof/transcript-domain-identifier/v1";
const PROOF_TRANSCRIPT_DOMAIN_LABEL: &[u8] = b"sealed-lattice/common-proof-transcript/v1";
const PROOF_TRANSCRIPT_DOMAIN_ENCODING_VERSION: u16 = 2;
const PROOF_RANDOMNESS_ASSIGNMENT_COUNT: usize = 9;
pub(crate) const TRACE_MASK_RANDOMNESS_PURPOSE_CLASS: u16 = 1;
pub(crate) const TELESCOPING_MASK_RANDOMNESS_PURPOSE_CLASS: u16 = 2;
pub(crate) const OPENING_MASK_RANDOMNESS_PURPOSE_CLASS: u16 = 3;
const PROOF_MASK_RANDOMNESS_PURPOSE_CLASSES: [u16; 3] = [
    TRACE_MASK_RANDOMNESS_PURPOSE_CLASS,
    TELESCOPING_MASK_RANDOMNESS_PURPOSE_CLASS,
    OPENING_MASK_RANDOMNESS_PURPOSE_CLASS,
];

#[derive(Clone, Copy)]
struct ProofRandomnessAssignment {
    family_schema_identifier: u16,
}

impl ProofRandomnessAssignment {
    const fn contains(self, purpose: u16) -> bool {
        purpose == PRIVATE_PROOF_SALT_PURPOSE || matches!(purpose, 1..=3)
    }
}

// These are the operative mask-purpose allocations consumed by the generated
// secret-bearing relation plans. Public-only families are intentionally absent:
// they allocate neither private masks nor a private proof-salt stream.
const PROOF_RANDOMNESS_ASSIGNMENTS: [ProofRandomnessAssignment; PROOF_RANDOMNESS_ASSIGNMENT_COUNT] = [
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    },
];

pub(crate) fn common_proof_transcript_domain_id() -> [u8; 64] {
    static DOMAIN_IDENTIFIER: OnceLock<[u8; 64]> = OnceLock::new();
    *DOMAIN_IDENTIFIER.get_or_init(|| {
        let mut canonical_assignment_bytes = Vec::with_capacity(
            6 + PROOF_MASK_RANDOMNESS_PURPOSE_CLASSES.len() * 2
                + PROOF_RANDOMNESS_ASSIGNMENTS.len() * 2,
        );
        canonical_assignment_bytes
            .extend_from_slice(&PROOF_TRANSCRIPT_DOMAIN_ENCODING_VERSION.to_le_bytes());
        canonical_assignment_bytes
            .extend_from_slice(&(PROOF_RANDOMNESS_ASSIGNMENT_COUNT as u16).to_le_bytes());
        canonical_assignment_bytes
            .extend_from_slice(&(PROOF_MASK_RANDOMNESS_PURPOSE_CLASSES.len() as u16).to_le_bytes());
        for purpose_class in PROOF_MASK_RANDOMNESS_PURPOSE_CLASSES {
            canonical_assignment_bytes.extend_from_slice(&purpose_class.to_le_bytes());
        }
        for assignment in PROOF_RANDOMNESS_ASSIGNMENTS {
            canonical_assignment_bytes
                .extend_from_slice(&assignment.family_schema_identifier.to_le_bytes());
        }

        hash512(
            PROOF_TRANSCRIPT_DOMAIN_HASH_DOMAIN,
            &[
                PROOF_TRANSCRIPT_DOMAIN_LABEL,
                &PRIVATE_PROOF_SALT_PURPOSE.to_le_bytes(),
                &canonical_assignment_bytes,
            ],
        )
    })
}

pub(crate) fn common_proof_randomness_purpose_is_assigned(
    family_schema_identifier: u16,
    purpose: u16,
) -> bool {
    PROOF_RANDOMNESS_ASSIGNMENTS
        .iter()
        .copied()
        .find(|assignment| assignment.family_schema_identifier == family_schema_identifier)
        .is_some_and(|assignment| assignment.contains(purpose))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProofRandomnessAssignmentVector {
        family_name: String,
        family_schema_identifier: u16,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProofRandomnessPurposeClassesVector {
        trace: u16,
        telescoping: u16,
        opening: u16,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProofRandomnessCoordinatesVector {
        private_proof_salt_purpose: u16,
        mask_purpose_classes: ProofRandomnessPurposeClassesVector,
        families: Vec<ProofRandomnessAssignmentVector>,
    }

    #[test]
    fn transcript_domain_identifier_is_deterministic_and_nonzero() {
        let first = common_proof_transcript_domain_id();
        let second = common_proof_transcript_domain_id();
        assert_eq!(first, second);
        assert_ne!(first, [0_u8; 64]);
    }

    #[test]
    fn proof_randomness_assignments_accept_only_bound_family_ranges() {
        for assignment in PROOF_RANDOMNESS_ASSIGNMENTS {
            assert!(common_proof_randomness_purpose_is_assigned(
                assignment.family_schema_identifier,
                TRACE_MASK_RANDOMNESS_PURPOSE_CLASS,
            ));
            assert!(common_proof_randomness_purpose_is_assigned(
                assignment.family_schema_identifier,
                TELESCOPING_MASK_RANDOMNESS_PURPOSE_CLASS,
            ));
            assert!(common_proof_randomness_purpose_is_assigned(
                assignment.family_schema_identifier,
                OPENING_MASK_RANDOMNESS_PURPOSE_CLASS,
            ));
            assert!(common_proof_randomness_purpose_is_assigned(
                assignment.family_schema_identifier,
                PRIVATE_PROOF_SALT_PURPOSE,
            ));
            assert!(!common_proof_randomness_purpose_is_assigned(
                assignment.family_schema_identifier,
                0,
            ));
        }

        for public_only_family in
            ProofApplicationSlotCeilings::PUBLIC_ONLY_FAMILY_SCHEMA_IDENTIFIERS
        {
            assert!(!common_proof_randomness_purpose_is_assigned(
                public_only_family,
                PRIVATE_PROOF_SALT_PURPOSE,
            ));
            assert!(!common_proof_randomness_purpose_is_assigned(
                public_only_family,
                1,
            ));
        }
        assert!(!common_proof_randomness_purpose_is_assigned(0xffff, 1));
        assert!(!common_proof_randomness_purpose_is_assigned(0x1211, 4));
        assert!(!common_proof_randomness_purpose_is_assigned(0x1217, 41));
    }

    #[test]
    fn proof_randomness_assignments_match_the_shared_runtime_vector() {
        let vector: ProofRandomnessCoordinatesVector = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/private-randomness-proof-coordinates.json"
        )))
        .expect("private-randomness proof-coordinate vector must parse");
        assert_eq!(
            vector.private_proof_salt_purpose,
            PRIVATE_PROOF_SALT_PURPOSE
        );
        assert_eq!(
            [
                vector.mask_purpose_classes.trace,
                vector.mask_purpose_classes.telescoping,
                vector.mask_purpose_classes.opening,
            ],
            PROOF_MASK_RANDOMNESS_PURPOSE_CLASSES,
        );
        assert_eq!(vector.families.len(), PROOF_RANDOMNESS_ASSIGNMENTS.len());

        let expected_family_names = [
            "sameSecret",
            "publicKeyShare",
            "relinearizationRoundOne",
            "relinearizationRoundTwo",
            "galoisKeyShare",
            "ballotValidity",
            "targetShareProof",
            "vssShareLinkage",
            "aggregateThresholdShare",
        ];
        for ((assignment, expected), expected_family_name) in PROOF_RANDOMNESS_ASSIGNMENTS
            .into_iter()
            .zip(vector.families)
            .zip(expected_family_names)
        {
            assert_eq!(expected.family_name, expected_family_name);
            assert_eq!(
                assignment.family_schema_identifier,
                expected.family_schema_identifier
            );
        }
    }
}
