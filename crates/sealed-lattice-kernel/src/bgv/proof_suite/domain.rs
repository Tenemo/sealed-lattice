use std::sync::OnceLock;

use crate::{
    foundation::{PRIVATE_PROOF_SALT_PURPOSE, ProofApplicationSlotCeilings},
    hashing::hash_framed_parts_512 as hash512,
};

const PROOF_TRANSCRIPT_DOMAIN_HASH_DOMAIN: &str =
    "sealed-lattice/proof/transcript-domain-identifier/v1";
const PROOF_TRANSCRIPT_DOMAIN_LABEL: &[u8] = b"sealed-lattice/common-proof-transcript/v1";
const PROOF_TRANSCRIPT_DOMAIN_ENCODING_VERSION: u16 = 1;
const PROOF_RANDOMNESS_ASSIGNMENT_COUNT: usize = 9;

#[derive(Clone, Copy)]
struct ProofRandomnessAssignment {
    family_schema_identifier: u16,
    first_mask_purpose: u16,
    last_mask_purpose: u16,
}

impl ProofRandomnessAssignment {
    const fn contains(self, purpose: u16) -> bool {
        purpose == PRIVATE_PROOF_SALT_PURPOSE
            || (purpose >= self.first_mask_purpose && purpose <= self.last_mask_purpose)
    }
}

// These are the operative mask-purpose allocations consumed by the generated
// secret-bearing relation plans. Public-only families are intentionally absent:
// they allocate neither private masks nor a private proof-salt stream.
const PROOF_RANDOMNESS_ASSIGNMENTS: [ProofRandomnessAssignment; PROOF_RANDOMNESS_ASSIGNMENT_COUNT] = [
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        first_mask_purpose: 1,
        last_mask_purpose: 2,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        first_mask_purpose: 3,
        last_mask_purpose: 4,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
        first_mask_purpose: 5,
        last_mask_purpose: 6,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
        first_mask_purpose: 7,
        last_mask_purpose: 8,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        first_mask_purpose: 9,
        last_mask_purpose: 40,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        first_mask_purpose: 41,
        last_mask_purpose: 42,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        first_mask_purpose: 43,
        last_mask_purpose: 44,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        first_mask_purpose: 45,
        last_mask_purpose: 46,
    },
    ProofRandomnessAssignment {
        family_schema_identifier:
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        first_mask_purpose: 47,
        last_mask_purpose: 48,
    },
];

pub(crate) fn common_proof_transcript_domain_id() -> [u8; 64] {
    static DOMAIN_IDENTIFIER: OnceLock<[u8; 64]> = OnceLock::new();
    *DOMAIN_IDENTIFIER.get_or_init(|| {
        let mut canonical_assignment_bytes =
            Vec::with_capacity(4 + PROOF_RANDOMNESS_ASSIGNMENTS.len() * 6);
        canonical_assignment_bytes
            .extend_from_slice(&PROOF_TRANSCRIPT_DOMAIN_ENCODING_VERSION.to_le_bytes());
        canonical_assignment_bytes
            .extend_from_slice(&(PROOF_RANDOMNESS_ASSIGNMENT_COUNT as u16).to_le_bytes());
        for assignment in PROOF_RANDOMNESS_ASSIGNMENTS {
            canonical_assignment_bytes
                .extend_from_slice(&assignment.family_schema_identifier.to_le_bytes());
            canonical_assignment_bytes
                .extend_from_slice(&assignment.first_mask_purpose.to_le_bytes());
            canonical_assignment_bytes
                .extend_from_slice(&assignment.last_mask_purpose.to_le_bytes());
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
        family_schema_identifier: u16,
        first_purpose: u16,
        last_purpose: u16,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProofRandomnessPurposeRangesVector {
        private_proof_salt_purpose: u16,
        ranges: Vec<ProofRandomnessAssignmentVector>,
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
                assignment.first_mask_purpose,
            ));
            assert!(common_proof_randomness_purpose_is_assigned(
                assignment.family_schema_identifier,
                assignment.last_mask_purpose,
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
        assert!(!common_proof_randomness_purpose_is_assigned(0x1211, 3));
        assert!(!common_proof_randomness_purpose_is_assigned(0x1217, 41));
    }

    #[test]
    fn proof_randomness_assignments_match_the_shared_runtime_vector() {
        let vector: ProofRandomnessPurposeRangesVector =
            serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../test-vectors/private-randomness-purpose-ranges.json"
            )))
            .expect("private-randomness purpose-range vector must parse");
        assert_eq!(
            vector.private_proof_salt_purpose,
            PRIVATE_PROOF_SALT_PURPOSE
        );
        assert_eq!(vector.ranges.len(), PROOF_RANDOMNESS_ASSIGNMENTS.len());

        for (assignment, expected) in PROOF_RANDOMNESS_ASSIGNMENTS.into_iter().zip(vector.ranges) {
            assert_eq!(
                assignment.family_schema_identifier,
                expected.family_schema_identifier
            );
            assert_eq!(assignment.first_mask_purpose, expected.first_purpose);
            assert_eq!(assignment.last_mask_purpose, expected.last_purpose);
        }
    }
}
