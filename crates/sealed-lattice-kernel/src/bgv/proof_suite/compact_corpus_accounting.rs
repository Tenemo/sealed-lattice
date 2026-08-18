//! Test-only compact proof-family corpus roll-up.
//!
//! The selected lifecycle inventory is production-derived. Compact byte
//! lengths remain evidence-bearing inputs, and a transport-only candidate is
//! never promoted into an accepted proof size or a complete corpus total.

use std::collections::{BTreeMap, BTreeSet};

use super::selected_accounting::derive_selected_proof_family_application_inventory;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactFamilySizeEvidenceStatus {
    TransportCandidate,
    AlgebraicallyVerified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactFamilySizeEvidence {
    pub(crate) application_statement_schema_identifier: u16,
    pub(crate) canonical_proof_byte_length: u64,
    pub(crate) status: CompactFamilySizeEvidenceStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactFamilyCorpusBlocker {
    MissingCompactSize,
    TransportCandidateNotAlgebraicallyVerified,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactFamilyCorpusRollup {
    pub(crate) application_statement_schema_identifier: u16,
    pub(crate) physical_proof_count: u32,
    pub(crate) logical_relation_instance_count: u32,
    pub(crate) candidate_canonical_proof_byte_length: Option<u64>,
    pub(crate) candidate_physical_corpus_byte_length: Option<u64>,
    pub(crate) accepted_canonical_proof_byte_length: Option<u64>,
    pub(crate) accepted_physical_corpus_byte_length: Option<u64>,
    pub(crate) blocker: Option<CompactFamilyCorpusBlocker>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactCorpusRollup {
    pub(crate) families: Vec<CompactFamilyCorpusRollup>,
    pub(crate) total_physical_proof_count: u32,
    pub(crate) total_logical_relation_instance_count: u32,
    pub(crate) accepted_canonical_corpus_byte_length: Option<u64>,
    pub(crate) blocked_family_schema_identifiers: BTreeSet<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactCorpusAccountingError {
    InvalidSelectedInventory,
    DuplicateFamilyEvidence,
    UnknownFamilyEvidence,
    ZeroByteLength,
    ArithmeticOverflow,
}

pub(crate) fn derive_selected_compact_corpus_rollup(
    size_evidence: &[CompactFamilySizeEvidence],
) -> Result<CompactCorpusRollup, CompactCorpusAccountingError> {
    let inventory = derive_selected_proof_family_application_inventory()
        .map_err(|_| CompactCorpusAccountingError::InvalidSelectedInventory)?;
    let inventory_schema_identifiers = inventory
        .ordered_family_entries()
        .iter()
        .map(|entry| entry.application_statement_schema_identifier())
        .collect::<BTreeSet<_>>();
    let mut evidence_by_schema_identifier = BTreeMap::new();
    for evidence in size_evidence {
        if evidence.canonical_proof_byte_length == 0 {
            return Err(CompactCorpusAccountingError::ZeroByteLength);
        }
        if !inventory_schema_identifiers.contains(&evidence.application_statement_schema_identifier)
        {
            return Err(CompactCorpusAccountingError::UnknownFamilyEvidence);
        }
        if evidence_by_schema_identifier
            .insert(evidence.application_statement_schema_identifier, *evidence)
            .is_some()
        {
            return Err(CompactCorpusAccountingError::DuplicateFamilyEvidence);
        }
    }

    let total_physical_proof_count = inventory
        .total_physical_proof_application_count()
        .map_err(|_| CompactCorpusAccountingError::InvalidSelectedInventory)?;
    let total_logical_relation_instance_count =
        inventory
            .total_logical_relation_instance_count()
            .map_err(|_| CompactCorpusAccountingError::InvalidSelectedInventory)?;
    let mut families = Vec::new();
    families
        .try_reserve_exact(inventory.ordered_family_entries().len())
        .map_err(|_| CompactCorpusAccountingError::ArithmeticOverflow)?;
    let mut accepted_canonical_corpus_byte_length = Some(0_u64);
    let mut blocked_family_schema_identifiers = BTreeSet::new();
    for inventory_entry in inventory.ordered_family_entries() {
        let schema_identifier = inventory_entry.application_statement_schema_identifier();
        let physical_proof_count = inventory_entry.physical_proof_application_count();
        let evidence = evidence_by_schema_identifier.get(&schema_identifier);
        let candidate_canonical_proof_byte_length = evidence.and_then(|evidence| {
            (evidence.status == CompactFamilySizeEvidenceStatus::TransportCandidate)
                .then_some(evidence.canonical_proof_byte_length)
        });
        let candidate_physical_corpus_byte_length = candidate_canonical_proof_byte_length
            .map(|byte_length| {
                byte_length
                    .checked_mul(u64::from(physical_proof_count))
                    .ok_or(CompactCorpusAccountingError::ArithmeticOverflow)
            })
            .transpose()?;
        let accepted_canonical_proof_byte_length = evidence.and_then(|evidence| {
            (evidence.status == CompactFamilySizeEvidenceStatus::AlgebraicallyVerified)
                .then_some(evidence.canonical_proof_byte_length)
        });
        let accepted_physical_corpus_byte_length = accepted_canonical_proof_byte_length
            .map(|byte_length| {
                byte_length
                    .checked_mul(u64::from(physical_proof_count))
                    .ok_or(CompactCorpusAccountingError::ArithmeticOverflow)
            })
            .transpose()?;
        let blocker = match evidence.map(|evidence| evidence.status) {
            None => Some(CompactFamilyCorpusBlocker::MissingCompactSize),
            Some(CompactFamilySizeEvidenceStatus::TransportCandidate) => {
                Some(CompactFamilyCorpusBlocker::TransportCandidateNotAlgebraicallyVerified)
            }
            Some(CompactFamilySizeEvidenceStatus::AlgebraicallyVerified) => None,
        };
        if blocker.is_some() {
            blocked_family_schema_identifiers.insert(schema_identifier);
            accepted_canonical_corpus_byte_length = None;
        } else if let (Some(total), Some(family_total)) = (
            accepted_canonical_corpus_byte_length,
            accepted_physical_corpus_byte_length,
        ) {
            accepted_canonical_corpus_byte_length = Some(
                total
                    .checked_add(family_total)
                    .ok_or(CompactCorpusAccountingError::ArithmeticOverflow)?,
            );
        }
        families.push(CompactFamilyCorpusRollup {
            application_statement_schema_identifier: schema_identifier,
            physical_proof_count,
            logical_relation_instance_count: inventory_entry.logical_relation_instance_count(),
            candidate_canonical_proof_byte_length,
            candidate_physical_corpus_byte_length,
            accepted_canonical_proof_byte_length,
            accepted_physical_corpus_byte_length,
            blocker,
        });
    }

    Ok(CompactCorpusRollup {
        families,
        total_physical_proof_count,
        total_logical_relation_instance_count,
        accepted_canonical_corpus_byte_length,
        blocked_family_schema_identifiers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_rollup_keeps_the_transport_candidate_and_unknown_sizes_blocking() {
        let rollup = derive_selected_compact_corpus_rollup(&[CompactFamilySizeEvidence {
            application_statement_schema_identifier: 0x1212,
            canonical_proof_byte_length: 23_815_474,
            status: CompactFamilySizeEvidenceStatus::TransportCandidate,
        }])
        .expect("selected compact corpus roll-up derives");

        assert_eq!(rollup.total_physical_proof_count, 103);
        assert_eq!(rollup.total_logical_relation_instance_count, 159);
        assert_eq!(rollup.families.len(), 12);
        assert_eq!(rollup.blocked_family_schema_identifiers.len(), 12);
        assert_eq!(rollup.accepted_canonical_corpus_byte_length, None);
        let public_key_share = rollup
            .families
            .iter()
            .find(|family| family.application_statement_schema_identifier == 0x1212)
            .expect("public-key-share family is inventoried");
        assert_eq!(public_key_share.physical_proof_count, 10);
        assert_eq!(public_key_share.logical_relation_instance_count, 10);
        assert_eq!(
            public_key_share.candidate_canonical_proof_byte_length,
            Some(23_815_474)
        );
        assert_eq!(
            public_key_share.candidate_physical_corpus_byte_length,
            Some(238_154_740)
        );
        assert_eq!(public_key_share.accepted_canonical_proof_byte_length, None);
        assert_eq!(public_key_share.accepted_physical_corpus_byte_length, None);
        assert_eq!(
            public_key_share.blocker,
            Some(CompactFamilyCorpusBlocker::TransportCandidateNotAlgebraicallyVerified)
        );
    }

    #[test]
    fn complete_rollup_requires_one_accepted_size_for_every_selected_family() {
        let inventory = derive_selected_proof_family_application_inventory()
            .expect("selected family inventory derives");
        let evidence = inventory
            .ordered_family_entries()
            .iter()
            .enumerate()
            .map(|(family_index, family)| CompactFamilySizeEvidence {
                application_statement_schema_identifier: family
                    .application_statement_schema_identifier(),
                canonical_proof_byte_length: u64::try_from(family_index + 1)
                    .expect("family index fits u64"),
                status: CompactFamilySizeEvidenceStatus::AlgebraicallyVerified,
            })
            .collect::<Vec<_>>();
        let expected_total = inventory
            .ordered_family_entries()
            .iter()
            .enumerate()
            .map(|(family_index, family)| {
                u64::try_from(family_index + 1).unwrap()
                    * u64::from(family.physical_proof_application_count())
            })
            .sum::<u64>();
        let rollup = derive_selected_compact_corpus_rollup(&evidence)
            .expect("complete accepted size inventory derives");

        assert!(rollup.blocked_family_schema_identifiers.is_empty());
        assert_eq!(
            rollup.accepted_canonical_corpus_byte_length,
            Some(expected_total)
        );
        assert!(
            rollup
                .families
                .iter()
                .all(|family| family.blocker.is_none())
        );
    }

    #[test]
    fn invalid_size_evidence_refuses_before_any_total_is_reported() {
        let valid = CompactFamilySizeEvidence {
            application_statement_schema_identifier: 0x1212,
            canonical_proof_byte_length: 1,
            status: CompactFamilySizeEvidenceStatus::TransportCandidate,
        };
        assert_eq!(
            derive_selected_compact_corpus_rollup(&[valid, valid]),
            Err(CompactCorpusAccountingError::DuplicateFamilyEvidence)
        );
        assert_eq!(
            derive_selected_compact_corpus_rollup(&[CompactFamilySizeEvidence {
                application_statement_schema_identifier: 0xffff,
                ..valid
            }]),
            Err(CompactCorpusAccountingError::UnknownFamilyEvidence)
        );
        assert_eq!(
            derive_selected_compact_corpus_rollup(&[CompactFamilySizeEvidence {
                canonical_proof_byte_length: 0,
                ..valid
            }]),
            Err(CompactCorpusAccountingError::ZeroByteLength)
        );
        assert_eq!(
            derive_selected_compact_corpus_rollup(&[CompactFamilySizeEvidence {
                canonical_proof_byte_length: u64::MAX,
                status: CompactFamilySizeEvidenceStatus::AlgebraicallyVerified,
                ..valid
            }]),
            Err(CompactCorpusAccountingError::ArithmeticOverflow)
        );
    }
}
