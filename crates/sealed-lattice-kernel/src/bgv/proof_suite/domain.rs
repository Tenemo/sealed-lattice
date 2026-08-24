use crate::foundation::{PRIVATE_PROOF_SALT_PURPOSE, ProofApplicationSlotCeilings};

const PROOF_RANDOMNESS_ASSIGNMENT_COUNT: usize = 12;
#[cfg(test)]
pub(crate) const TRACE_MASK_RANDOMNESS_PURPOSE_CLASS: u16 = 1;
#[cfg(test)]
pub(crate) const TELESCOPING_MASK_RANDOMNESS_PURPOSE_CLASS: u16 = 2;
#[cfg(test)]
pub(crate) const OPENING_MASK_RANDOMNESS_PURPOSE_CLASS: u16 = 3;
#[cfg(test)]
const PROOF_MASK_RANDOMNESS_PURPOSE_CLASSES: [u16; 3] = [
    TRACE_MASK_RANDOMNESS_PURPOSE_CLASS,
    TELESCOPING_MASK_RANDOMNESS_PURPOSE_CLASS,
    OPENING_MASK_RANDOMNESS_PURPOSE_CLASS,
];
pub(crate) const HIDING_ARGUMENT_RANDOMNESS_PURPOSE_CLASS: u16 = 4;

#[derive(Clone, Copy)]
struct ProofRandomnessAssignment {
    family_schema_identifier: u16,
    relation_witness_is_private: bool,
}

impl ProofRandomnessAssignment {
    const fn secret_bearing(family_schema_identifier: u16) -> Self {
        Self {
            family_schema_identifier,
            relation_witness_is_private: true,
        }
    }

    const fn public_witness(family_schema_identifier: u16) -> Self {
        Self {
            family_schema_identifier,
            relation_witness_is_private: false,
        }
    }

    const fn contains(self, purpose: u16) -> bool {
        purpose == HIDING_ARGUMENT_RANDOMNESS_PURPOSE_CLASS
            || (self.relation_witness_is_private
                && (purpose == PRIVATE_PROOF_SALT_PURPOSE || matches!(purpose, 1..=3)))
    }
}

// Every family receives an independently keyed aggregate-wide hiding stream.
// Only secret-bearing relation plans receive relation-mask and row-pad streams.
const PROOF_RANDOMNESS_ASSIGNMENTS: [ProofRandomnessAssignment; PROOF_RANDOMNESS_ASSIGNMENT_COUNT] = [
    ProofRandomnessAssignment::secret_bearing(
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    ),
    ProofRandomnessAssignment::secret_bearing(
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    ),
    ProofRandomnessAssignment::public_witness(
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    ),
    ProofRandomnessAssignment::secret_bearing(
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
    ),
    ProofRandomnessAssignment::public_witness(
        ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    ),
    ProofRandomnessAssignment::secret_bearing(
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
    ),
    ProofRandomnessAssignment::secret_bearing(
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    ),
    ProofRandomnessAssignment::public_witness(
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
    ),
    ProofRandomnessAssignment::secret_bearing(
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
    ),
    ProofRandomnessAssignment::secret_bearing(
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
    ),
    ProofRandomnessAssignment::secret_bearing(
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
    ),
    ProofRandomnessAssignment::secret_bearing(
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    ),
];

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
        relation_witness_is_private: bool,
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
        hiding_argument_purpose: u16,
        mask_purpose_classes: ProofRandomnessPurposeClassesVector,
        families: Vec<ProofRandomnessAssignmentVector>,
    }

    #[test]
    fn proof_randomness_assignments_accept_only_bound_family_ranges() {
        let assigned_family_schema_identifiers = PROOF_RANDOMNESS_ASSIGNMENTS
            .iter()
            .map(|assignment| assignment.family_schema_identifier)
            .collect::<std::collections::BTreeSet<_>>();
        for assignment in PROOF_RANDOMNESS_ASSIGNMENTS {
            for relation_mask_purpose in PROOF_MASK_RANDOMNESS_PURPOSE_CLASSES {
                assert_eq!(
                    common_proof_randomness_purpose_is_assigned(
                        assignment.family_schema_identifier,
                        relation_mask_purpose,
                    ),
                    assignment.relation_witness_is_private,
                );
            }
            assert!(common_proof_randomness_purpose_is_assigned(
                assignment.family_schema_identifier,
                HIDING_ARGUMENT_RANDOMNESS_PURPOSE_CLASS,
            ));
            assert_eq!(
                common_proof_randomness_purpose_is_assigned(
                    assignment.family_schema_identifier,
                    PRIVATE_PROOF_SALT_PURPOSE,
                ),
                assignment.relation_witness_is_private,
            );
            assert!(!common_proof_randomness_purpose_is_assigned(
                assignment.family_schema_identifier,
                5,
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
            assert!(common_proof_randomness_purpose_is_assigned(
                public_only_family,
                HIDING_ARGUMENT_RANDOMNESS_PURPOSE_CLASS,
            ));
        }
        let adjacent_unassigned_family_schema_identifiers = assigned_family_schema_identifiers
            .iter()
            .flat_map(|family_schema_identifier| {
                [
                    family_schema_identifier.checked_sub(1),
                    family_schema_identifier.checked_add(1),
                ]
            })
            .flatten()
            .filter(|family_schema_identifier| {
                !assigned_family_schema_identifiers.contains(family_schema_identifier)
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert!(!adjacent_unassigned_family_schema_identifiers.is_empty());
        for family_schema_identifier in adjacent_unassigned_family_schema_identifiers {
            for purpose in [
                PRIVATE_PROOF_SALT_PURPOSE,
                TRACE_MASK_RANDOMNESS_PURPOSE_CLASS,
                TELESCOPING_MASK_RANDOMNESS_PURPOSE_CLASS,
                OPENING_MASK_RANDOMNESS_PURPOSE_CLASS,
                HIDING_ARGUMENT_RANDOMNESS_PURPOSE_CLASS,
            ] {
                assert!(!common_proof_randomness_purpose_is_assigned(
                    family_schema_identifier,
                    purpose,
                ));
            }
        }
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
        assert_eq!(
            vector.hiding_argument_purpose,
            HIDING_ARGUMENT_RANDOMNESS_PURPOSE_CLASS,
        );
        assert_eq!(vector.families.len(), PROOF_RANDOMNESS_ASSIGNMENTS.len());

        let expected_family_names = [
            "sameSecret",
            "publicKeyShare",
            "collectivePublicKeyAggregate",
            "relinearizationRoundOne",
            "relinearizationRoundOneAggregate",
            "relinearizationRoundTwo",
            "galoisKeyShare",
            "evaluatorKeyAggregate",
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
            assert_eq!(
                assignment.relation_witness_is_private,
                expected.relation_witness_is_private,
            );
        }
    }
}
