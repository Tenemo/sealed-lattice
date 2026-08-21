//! Compiler-owned readiness record for the selected compact construction.
//!
//! This module is test-only evidence. It recomputes the unactivated canonical
//! suite record, lifecycle application inventory, complete relation catalog,
//! and every currently available compact verifier contract. The resulting
//! fingerprint is not a suite identifier, evidence identity, capability, or
//! verifier input. Final candidate evidence remains unavailable until all
//! family contracts and the exact scalar release-WASM proof ABI are present.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

use crate::{
    foundation::{
        CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512, ProofApplicationSlotCeilings,
        SuiteRecord, derive_unactivated_selected_suite_candidate_record_from_relation_plans,
    },
    hashing::hash_framed_parts_512,
};

use super::{
    compact_proof_contract::selected_compact_public_key_proof_contract,
    relation_plan::{RelationColumnOrigin, RelationTreeDescriptor},
    selected_accounting::derive_selected_proof_family_application_inventory,
    selected_relation_plans,
};

const CONSTRUCTION_MAGIC: [u8; 8] = *b"SLCCC001";
const CONSTRUCTION_VERSION: u16 = 1;
const CONSTRUCTION_HASH_DOMAIN: &str = "sealed-lattice/bgv/compact-candidate-construction/v1";
const CONSTRUCTION_INPUT_HASH_DOMAIN: &str =
    "sealed-lattice/bgv/compact-candidate-construction/input/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactCandidateConstructionError {
    InvalidSelectedSuite,
    InvalidApplicationInventory,
    InvalidRelationCatalog,
    InvalidCompactContract,
    DuplicateRelationFamily(u16),
    MissingRelationFamily(u16),
    UnknownRelationFamily(u16),
    DuplicateCompactContract(u16),
    UnknownCompactContract(u16),
    CompactContractRelationMismatch(u16),
    CountOverflow,
    SuppliedInputCountMismatch { expected: usize, actual: usize },
    SuppliedInputMismatch { ordinal: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactCandidateEvidenceBlocker {
    MissingCompactProofContract(u16),
    MissingScalarReleaseWasmProofAbi,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactContractReference {
    application_statement_schema_identifier: u16,
    canonical_contract_byte_length: u64,
    canonical_contract_hash: [u8; Hash512::BYTE_LENGTH],
    relation_plan_variant_hash: [u8; Hash512::BYTE_LENGTH],
    public_input_ring_vector_count: u64,
    source_correspondence_public_column_count: u32,
    witness_ring_vector_count: u64,
    operative_constraint_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactRelationVariantSummary {
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    proof_privacy_mode: u16,
    canonical_variant_hash: [u8; Hash512::BYTE_LENGTH],
    verifier_source_count: u32,
    verifier_sequence_column_count: u32,
    bound_tree_column_count: u32,
    prover_column_count: u32,
    bound_public_root_count: u32,
    tree_count: u32,
    constraint_count: u64,
    opening_point_count: u32,
    opening_claim_count: u32,
    mask_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactCandidateFamilyEntry {
    application_statement_schema_identifier: u16,
    physical_proof_application_count: u32,
    logical_relation_instance_count: u32,
    canonical_relation_plan_byte_length: u64,
    canonical_relation_plan_hash: [u8; Hash512::BYTE_LENGTH],
    variants: Vec<CompactRelationVariantSummary>,
    compact_contract: Option<CompactContractReference>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactRelationPlanSummary {
    canonical_relation_plan_byte_length: u64,
    canonical_relation_plan_hash: [u8; Hash512::BYTE_LENGTH],
    variants: Vec<CompactRelationVariantSummary>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactCandidateInputKind {
    CanonicalSuiteRecord = 1,
    ProofFamilyConstruction = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactCandidateInputReference {
    kind: CompactCandidateInputKind,
    coordinate: u32,
    canonical_byte_length: u64,
    canonical_hash: [u8; Hash512::BYTE_LENGTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SelectedCompactCandidateConstruction {
    canonical_suite_record_bytes: Vec<u8>,
    ordered_families: Vec<CompactCandidateFamilyEntry>,
    total_physical_proof_application_count: u32,
    total_logical_relation_instance_count: u32,
    scalar_release_wasm_proof_abi_available: bool,
}

impl SelectedCompactCandidateConstruction {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CompactCandidateConstructionError> {
        let mut writer = CandidateConstructionWriter::new();
        writer.write_fixed(&CONSTRUCTION_MAGIC);
        writer.write_u16(CONSTRUCTION_VERSION);
        writer.write_variable_bytes(&self.canonical_suite_record_bytes)?;
        writer.write_u32(self.total_physical_proof_application_count);
        writer.write_u32(self.total_logical_relation_instance_count);
        writer.write_count(self.ordered_families.len())?;
        for family in &self.ordered_families {
            writer.write_variable_bytes(&family.canonical_bytes()?)?;
        }
        writer.write_u8(u8::from(self.scalar_release_wasm_proof_abi_available));
        Ok(writer.finish())
    }

    fn construction_hash(
        &self,
    ) -> Result<[u8; Hash512::BYTE_LENGTH], CompactCandidateConstructionError> {
        let canonical_bytes = self.canonical_bytes()?;
        Ok(hash_framed_parts_512(
            CONSTRUCTION_HASH_DOMAIN,
            &[canonical_bytes.as_slice()],
        ))
    }

    fn evidence_blockers(&self) -> Vec<CompactCandidateEvidenceBlocker> {
        let mut blockers = self
            .ordered_families
            .iter()
            .filter_map(|family| {
                family.compact_contract.is_none().then_some(
                    CompactCandidateEvidenceBlocker::MissingCompactProofContract(
                        family.application_statement_schema_identifier,
                    ),
                )
            })
            .collect::<Vec<_>>();
        if !self.scalar_release_wasm_proof_abi_available {
            blockers.push(CompactCandidateEvidenceBlocker::MissingScalarReleaseWasmProofAbi);
        }
        blockers
    }

    fn ordered_input_references(
        &self,
    ) -> Result<Vec<CompactCandidateInputReference>, CompactCandidateConstructionError> {
        let mut references = Vec::new();
        references
            .try_reserve_exact(
                1_usize
                    .checked_add(self.ordered_families.len())
                    .ok_or(CompactCandidateConstructionError::CountOverflow)?,
            )
            .map_err(|_| CompactCandidateConstructionError::CountOverflow)?;
        references.push(input_reference(
            CompactCandidateInputKind::CanonicalSuiteRecord,
            0,
            &self.canonical_suite_record_bytes,
        )?);
        for (family_ordinal, family) in self.ordered_families.iter().enumerate() {
            references.push(input_reference(
                CompactCandidateInputKind::ProofFamilyConstruction,
                u32::try_from(family_ordinal)
                    .map_err(|_| CompactCandidateConstructionError::CountOverflow)?,
                &family.canonical_bytes()?,
            )?);
        }
        Ok(references)
    }
}

impl CompactCandidateFamilyEntry {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CompactCandidateConstructionError> {
        let mut writer = CandidateConstructionWriter::new();
        writer.write_u16(self.application_statement_schema_identifier);
        writer.write_u32(self.physical_proof_application_count);
        writer.write_u32(self.logical_relation_instance_count);
        writer.write_u64(self.canonical_relation_plan_byte_length);
        writer.write_fixed(&self.canonical_relation_plan_hash);
        writer.write_count(self.variants.len())?;
        for variant in &self.variants {
            variant.encode(&mut writer);
        }
        match self.compact_contract {
            Some(reference) => {
                writer.write_u8(1);
                reference.encode(&mut writer);
            }
            None => writer.write_u8(0),
        }
        Ok(writer.finish())
    }
}

impl CompactRelationVariantSummary {
    fn encode(self, writer: &mut CandidateConstructionWriter) {
        writer.write_optional_u32(self.schedule_position);
        writer.write_optional_u16(self.top_count);
        writer.write_u16(self.proof_privacy_mode);
        writer.write_fixed(&self.canonical_variant_hash);
        writer.write_u32(self.verifier_source_count);
        writer.write_u32(self.verifier_sequence_column_count);
        writer.write_u32(self.bound_tree_column_count);
        writer.write_u32(self.prover_column_count);
        writer.write_u32(self.bound_public_root_count);
        writer.write_u32(self.tree_count);
        writer.write_u64(self.constraint_count);
        writer.write_u32(self.opening_point_count);
        writer.write_u32(self.opening_claim_count);
        writer.write_u32(self.mask_count);
    }
}

impl CompactContractReference {
    fn encode(self, writer: &mut CandidateConstructionWriter) {
        writer.write_u16(self.application_statement_schema_identifier);
        writer.write_u64(self.canonical_contract_byte_length);
        writer.write_fixed(&self.canonical_contract_hash);
        writer.write_fixed(&self.relation_plan_variant_hash);
        writer.write_u64(self.public_input_ring_vector_count);
        writer.write_u32(self.source_correspondence_public_column_count);
        writer.write_u64(self.witness_ring_vector_count);
        writer.write_u64(self.operative_constraint_count);
    }
}

static SELECTED_COMPACT_CANDIDATE_CONSTRUCTION: OnceLock<
    Result<SelectedCompactCandidateConstruction, CompactCandidateConstructionError>,
> = OnceLock::new();

fn derive_selected_compact_candidate_construction()
-> Result<SelectedCompactCandidateConstruction, CompactCandidateConstructionError> {
    SELECTED_COMPACT_CANDIDATE_CONSTRUCTION
        .get_or_init(derive_selected_compact_candidate_construction_uncached)
        .clone()
}

fn derive_selected_compact_candidate_construction_uncached()
-> Result<SelectedCompactCandidateConstruction, CompactCandidateConstructionError> {
    let application_inventory = derive_selected_proof_family_application_inventory()
        .map_err(|_| CompactCandidateConstructionError::InvalidApplicationInventory)?;
    let relation_plans = selected_relation_plans()
        .map_err(|_| CompactCandidateConstructionError::InvalidRelationCatalog)?;
    let mut relation_plans_by_family = BTreeMap::new();
    for relation_plan in &relation_plans {
        let schema_identifier = relation_plan.application_statement_schema_identifier();
        let variants = relation_plan
            .compiled_plan()
            .variants()
            .iter()
            .map(derive_relation_variant_summary)
            .collect::<Result<Vec<_>, _>>()?;
        if variants.is_empty() {
            return Err(CompactCandidateConstructionError::InvalidRelationCatalog);
        }
        if relation_plans_by_family
            .insert(
                schema_identifier,
                CompactRelationPlanSummary {
                    canonical_relation_plan_byte_length: relation_plan.canonical_plan_byte_length(),
                    canonical_relation_plan_hash: relation_plan.canonical_plan_hash(),
                    variants,
                },
            )
            .is_some()
        {
            return Err(CompactCandidateConstructionError::DuplicateRelationFamily(
                schema_identifier,
            ));
        }
    }
    let canonical_suite_record_bytes =
        derive_unactivated_selected_suite_candidate_record_from_relation_plans(relation_plans)
            .and_then(|record| record.encode())
            .map_err(|_| CompactCandidateConstructionError::InvalidSelectedSuite)?;
    SuiteRecord::decode(
        &canonical_suite_record_bytes,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| CompactCandidateConstructionError::InvalidSelectedSuite)?;

    let compact_contracts = derive_available_compact_contracts()?;
    let mut compact_contracts_by_family = BTreeMap::new();
    for contract in compact_contracts {
        if compact_contracts_by_family
            .insert(contract.application_statement_schema_identifier, contract)
            .is_some()
        {
            return Err(CompactCandidateConstructionError::DuplicateCompactContract(
                contract.application_statement_schema_identifier,
            ));
        }
    }

    let inventory_family_identifiers = application_inventory
        .ordered_family_entries()
        .iter()
        .map(|entry| entry.application_statement_schema_identifier())
        .collect::<BTreeSet<_>>();
    if let Some(unknown_family) = relation_plans_by_family
        .keys()
        .copied()
        .find(|family| !inventory_family_identifiers.contains(family))
    {
        return Err(CompactCandidateConstructionError::UnknownRelationFamily(
            unknown_family,
        ));
    }
    if let Some(unknown_family) = compact_contracts_by_family
        .keys()
        .copied()
        .find(|family| !inventory_family_identifiers.contains(family))
    {
        return Err(CompactCandidateConstructionError::UnknownCompactContract(
            unknown_family,
        ));
    }

    let mut ordered_families = Vec::new();
    ordered_families
        .try_reserve_exact(application_inventory.ordered_family_entries().len())
        .map_err(|_| CompactCandidateConstructionError::CountOverflow)?;
    for inventory_entry in application_inventory.ordered_family_entries() {
        let schema_identifier = inventory_entry.application_statement_schema_identifier();
        let relation_plan = relation_plans_by_family.remove(&schema_identifier).ok_or(
            CompactCandidateConstructionError::MissingRelationFamily(schema_identifier),
        )?;
        let compact_contract = compact_contracts_by_family.remove(&schema_identifier);
        if compact_contract.is_some_and(|contract| {
            relation_plan.variants.len() != 1
                || relation_plan.variants[0].canonical_variant_hash
                    != contract.relation_plan_variant_hash
        }) {
            return Err(
                CompactCandidateConstructionError::CompactContractRelationMismatch(
                    schema_identifier,
                ),
            );
        }
        ordered_families.push(CompactCandidateFamilyEntry {
            application_statement_schema_identifier: schema_identifier,
            physical_proof_application_count: inventory_entry.physical_proof_application_count(),
            logical_relation_instance_count: inventory_entry.logical_relation_instance_count(),
            canonical_relation_plan_byte_length: relation_plan.canonical_relation_plan_byte_length,
            canonical_relation_plan_hash: relation_plan.canonical_relation_plan_hash,
            variants: relation_plan.variants,
            compact_contract,
        });
    }
    if !relation_plans_by_family.is_empty() || !compact_contracts_by_family.is_empty() {
        return Err(CompactCandidateConstructionError::InvalidRelationCatalog);
    }

    Ok(SelectedCompactCandidateConstruction {
        canonical_suite_record_bytes,
        ordered_families,
        total_physical_proof_application_count: application_inventory
            .total_physical_proof_application_count()
            .map_err(|_| CompactCandidateConstructionError::InvalidApplicationInventory)?,
        total_logical_relation_instance_count: application_inventory
            .total_logical_relation_instance_count()
            .map_err(|_| CompactCandidateConstructionError::InvalidApplicationInventory)?,
        // The current WASM build does not expose the complete compact family
        // generation-and-verification ABI. Merely hashing whatever artifact is
        // present on disk would falsely promote an unrelated build input.
        scalar_release_wasm_proof_abi_available: false,
    })
}

fn derive_available_compact_contracts()
-> Result<Vec<CompactContractReference>, CompactCandidateConstructionError> {
    let contract = selected_compact_public_key_proof_contract()
        .map_err(|_| CompactCandidateConstructionError::InvalidCompactContract)?;
    let verifier_inputs = contract.verifier_inputs();
    let (canonical_contract_byte_length, canonical_contract_hash) = verifier_inputs
        .canonical_source_byte_length_and_hash()
        .map_err(|_| CompactCandidateConstructionError::InvalidCompactContract)?;
    let source_correspondence_public_column_count = verifier_inputs
        .relation
        .ordered_public_vectors()
        .iter()
        .try_fold(0_u32, |count, vector| {
            u32::try_from(vector.column_ordinals().len())
                .ok()
                .and_then(|width| count.checked_add(width))
                .ok_or(CompactCandidateConstructionError::CountOverflow)
        })?;
    Ok(vec![CompactContractReference {
        application_statement_schema_identifier:
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        canonical_contract_byte_length,
        canonical_contract_hash: canonical_contract_hash.into_bytes(),
        relation_plan_variant_hash: verifier_inputs.relation.relation_plan_variant_hash(),
        public_input_ring_vector_count: verifier_inputs.relation.public_input_ring_vector_count(),
        source_correspondence_public_column_count,
        witness_ring_vector_count: verifier_inputs.relation.witness_ring_vector_count(),
        operative_constraint_count: verifier_inputs.relation.operative_constraint_count(),
    }])
}

fn derive_relation_variant_summary(
    variant: &super::RelationPlanVariant,
) -> Result<CompactRelationVariantSummary, CompactCandidateConstructionError> {
    let mut verifier_sequence_column_count = 0_u32;
    let mut bound_tree_column_count = 0_u32;
    let mut prover_column_count = 0_u32;
    for column in variant.ordered_columns() {
        let count = match column.origin() {
            RelationColumnOrigin::VerifierSequence { .. } => &mut verifier_sequence_column_count,
            RelationColumnOrigin::BoundTree { .. } => &mut bound_tree_column_count,
            RelationColumnOrigin::Prover => &mut prover_column_count,
        };
        *count = count
            .checked_add(1)
            .ok_or(CompactCandidateConstructionError::CountOverflow)?;
    }
    let bound_public_root_count = u32::try_from(
        variant
            .ordered_trees()
            .iter()
            .filter_map(|tree| match tree {
                RelationTreeDescriptor::BoundPublic {
                    expected_root_source_ordinal,
                    ..
                } => Some(*expected_root_source_ordinal),
                RelationTreeDescriptor::ProofCreated { .. } => None,
            })
            .collect::<BTreeSet<_>>()
            .len(),
    )
    .map_err(|_| CompactCandidateConstructionError::CountOverflow)?;
    Ok(CompactRelationVariantSummary {
        schedule_position: variant.schedule_position(),
        top_count: variant.top_count(),
        proof_privacy_mode: variant.proof_privacy_mode() as u16,
        canonical_variant_hash: variant
            .canonical_hash()
            .map_err(|_| CompactCandidateConstructionError::InvalidRelationCatalog)?,
        verifier_source_count: u32::try_from(variant.ordered_verifier_source_count())
            .map_err(|_| CompactCandidateConstructionError::CountOverflow)?,
        verifier_sequence_column_count,
        bound_tree_column_count,
        prover_column_count,
        bound_public_root_count,
        tree_count: u32::try_from(variant.ordered_trees().len())
            .map_err(|_| CompactCandidateConstructionError::CountOverflow)?,
        constraint_count: u64::try_from(variant.ordered_constraint_count())
            .map_err(|_| CompactCandidateConstructionError::CountOverflow)?,
        opening_point_count: u32::try_from(variant.ordered_opening_points().len())
            .map_err(|_| CompactCandidateConstructionError::CountOverflow)?,
        opening_claim_count: u32::try_from(variant.ordered_opening_claims().len())
            .map_err(|_| CompactCandidateConstructionError::CountOverflow)?,
        mask_count: u32::try_from(variant.ordered_masks().len())
            .map_err(|_| CompactCandidateConstructionError::CountOverflow)?,
    })
}

fn input_reference(
    kind: CompactCandidateInputKind,
    coordinate: u32,
    canonical_bytes: &[u8],
) -> Result<CompactCandidateInputReference, CompactCandidateConstructionError> {
    Ok(CompactCandidateInputReference {
        kind,
        coordinate,
        canonical_byte_length: u64::try_from(canonical_bytes.len())
            .map_err(|_| CompactCandidateConstructionError::CountOverflow)?,
        canonical_hash: hash_framed_parts_512(
            CONSTRUCTION_INPUT_HASH_DOMAIN,
            &[
                &(kind as u16).to_le_bytes(),
                &coordinate.to_le_bytes(),
                canonical_bytes,
            ],
        ),
    })
}

fn verify_recomputed_candidate_input_inventory(
    supplied: &[CompactCandidateInputReference],
) -> Result<(), CompactCandidateConstructionError> {
    let expected = derive_selected_compact_candidate_construction()?.ordered_input_references()?;
    if supplied.len() != expected.len() {
        return Err(
            CompactCandidateConstructionError::SuppliedInputCountMismatch {
                expected: expected.len(),
                actual: supplied.len(),
            },
        );
    }
    if let Some(ordinal) = expected
        .iter()
        .zip(supplied)
        .position(|(expected, supplied)| expected != supplied)
    {
        return Err(CompactCandidateConstructionError::SuppliedInputMismatch { ordinal });
    }
    Ok(())
}

struct CandidateConstructionWriter {
    bytes: Vec<u8>,
}

impl CandidateConstructionWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_fixed<const BYTE_LENGTH: usize>(&mut self, value: &[u8; BYTE_LENGTH]) {
        self.bytes.extend_from_slice(value);
    }

    fn write_count(&mut self, count: usize) -> Result<(), CompactCandidateConstructionError> {
        self.write_u32(
            u32::try_from(count).map_err(|_| CompactCandidateConstructionError::CountOverflow)?,
        );
        Ok(())
    }

    fn write_variable_bytes(
        &mut self,
        value: &[u8],
    ) -> Result<(), CompactCandidateConstructionError> {
        self.write_u64(
            u64::try_from(value.len())
                .map_err(|_| CompactCandidateConstructionError::CountOverflow)?,
        );
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn write_optional_u16(&mut self, value: Option<u16>) {
        match value {
            Some(value) => {
                self.write_u8(1);
                self.write_u16(value);
            }
            None => self.write_u8(0),
        }
    }

    fn write_optional_u32(&mut self, value: Option<u32>) {
        match value {
            Some(value) => {
                self.write_u8(1);
                self.write_u32(value);
            }
            None => self.write_u8(0),
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use crate::bgv::{
        key_switch_topology::{KEY_SWITCH_DATA_PRIMES_PER_BLOCK, KEY_SWITCH_SPECIAL_PRIMES},
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    };

    use super::*;

    #[test]
    fn selected_compact_candidate_derives_exact_profile_from_canonical_authorities() {
        let construction = derive_selected_compact_candidate_construction()
            .expect("selected compact candidate construction derives");
        let suite = SuiteRecord::decode(
            &construction.canonical_suite_record_bytes,
            &CanonicalDecodeLimits::default(),
        )
        .expect("unactivated selected suite record decodes canonically");

        assert_eq!(suite.roster_size(), FOUNDATION_PROFILE.participant_count);
        assert_eq!(suite.option_count(), FOUNDATION_PROFILE.option_count);
        assert_eq!(suite.polynomial_degree(), POLYNOMIAL_DEGREE as u32);
        assert_eq!(suite.plaintext_modulus(), PLAINTEXT_MODULUS);
        assert_eq!(suite.ordered_data_primes(), DATA_PRIMES);
        assert_eq!(suite.ordered_special_primes(), KEY_SWITCH_SPECIAL_PRIMES);
        assert_eq!(
            suite.key_switch_data_primes_per_block(),
            KEY_SWITCH_DATA_PRIMES_PER_BLOCK as u16
        );
        assert_eq!(construction.ordered_families.len(), 12);
        assert_eq!(construction.total_physical_proof_application_count, 103);
        assert_eq!(construction.total_logical_relation_instance_count, 159);
        assert!(construction.ordered_families.iter().all(|family| {
            family.canonical_relation_plan_byte_length > 0
                && family.canonical_relation_plan_hash != [0_u8; Hash512::BYTE_LENGTH]
                && !family.variants.is_empty()
        }));

        let public_key = construction
            .ordered_families
            .iter()
            .find(|family| {
                family.application_statement_schema_identifier
                    == ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            })
            .expect("public-key-share family is present");
        let [public_key_variant] = public_key.variants.as_slice() else {
            panic!("public-key-share family must have one selected relation variant");
        };
        assert_eq!(public_key.physical_proof_application_count, 10);
        assert_eq!(public_key.logical_relation_instance_count, 10);
        assert_eq!(public_key_variant.verifier_sequence_column_count, 64);
        assert_eq!(public_key_variant.bound_public_root_count, 4);
        let public_key_contract = public_key
            .compact_contract
            .expect("the reference compact contract is present");
        assert_eq!(public_key_contract.public_input_ring_vector_count, 61);
        assert_eq!(
            public_key_contract.source_correspondence_public_column_count,
            122
        );
        assert_eq!(
            public_key_contract.relation_plan_variant_hash,
            public_key_variant.canonical_variant_hash
        );

        let first_hash = construction
            .construction_hash()
            .expect("construction hash derives");
        let second_hash = derive_selected_compact_candidate_construction()
            .expect("selected compact candidate construction rederives")
            .construction_hash()
            .expect("second construction hash derives");
        assert_eq!(first_hash, second_hash);
    }

    #[test]
    fn recomputed_candidate_inventory_rejects_omission_duplicate_reordering_and_mutation() {
        let construction = derive_selected_compact_candidate_construction()
            .expect("selected compact candidate construction derives");
        let inputs = construction
            .ordered_input_references()
            .expect("candidate input inventory derives");
        verify_recomputed_candidate_input_inventory(&inputs)
            .expect("the independently recomputed input inventory matches");

        let mut omitted = inputs.clone();
        omitted.remove(1);
        assert_eq!(
            verify_recomputed_candidate_input_inventory(&omitted),
            Err(
                CompactCandidateConstructionError::SuppliedInputCountMismatch {
                    expected: inputs.len(),
                    actual: inputs.len() - 1,
                }
            )
        );

        let mut duplicated = inputs.clone();
        duplicated.push(inputs[1]);
        assert_eq!(
            verify_recomputed_candidate_input_inventory(&duplicated),
            Err(
                CompactCandidateConstructionError::SuppliedInputCountMismatch {
                    expected: inputs.len(),
                    actual: inputs.len() + 1,
                }
            )
        );

        let mut reordered = inputs.clone();
        reordered.swap(1, 2);
        assert_eq!(
            verify_recomputed_candidate_input_inventory(&reordered),
            Err(CompactCandidateConstructionError::SuppliedInputMismatch { ordinal: 1 })
        );

        let mut mutated = inputs.clone();
        mutated[4].canonical_hash[17] ^= 1;
        assert_eq!(
            verify_recomputed_candidate_input_inventory(&mutated),
            Err(CompactCandidateConstructionError::SuppliedInputMismatch { ordinal: 4 })
        );
    }

    #[test]
    fn candidate_evidence_stays_blocked_on_missing_contracts_and_scalar_wasm_abi() {
        let construction = derive_selected_compact_candidate_construction()
            .expect("selected compact candidate construction derives");
        let blockers = construction.evidence_blockers();
        let missing_contracts = blockers
            .iter()
            .filter_map(|blocker| match blocker {
                CompactCandidateEvidenceBlocker::MissingCompactProofContract(family) => {
                    Some(*family)
                }
                CompactCandidateEvidenceBlocker::MissingScalarReleaseWasmProofAbi => None,
            })
            .collect::<Vec<_>>();
        let expected_missing_contracts = construction
            .ordered_families
            .iter()
            .filter(|family| {
                family.application_statement_schema_identifier
                    != ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            })
            .map(|family| family.application_statement_schema_identifier)
            .collect::<Vec<_>>();

        assert_eq!(missing_contracts, expected_missing_contracts);
        assert_eq!(missing_contracts.len(), 11);
        assert_eq!(
            blockers.last(),
            Some(&CompactCandidateEvidenceBlocker::MissingScalarReleaseWasmProofAbi)
        );
    }

    #[test]
    fn every_operative_candidate_row_changes_the_construction_fingerprint() {
        let construction = derive_selected_compact_candidate_construction()
            .expect("selected compact candidate construction derives");
        let baseline_hash = construction
            .construction_hash()
            .expect("baseline construction hash derives");

        let mut suite_mutation = construction.clone();
        suite_mutation.canonical_suite_record_bytes[0] ^= 1;
        assert_ne!(
            suite_mutation.construction_hash().unwrap(),
            baseline_hash,
            "suite bytes must bind the construction fingerprint"
        );

        let mut inventory_mutation = construction.clone();
        inventory_mutation.ordered_families[0].physical_proof_application_count += 1;
        assert_ne!(
            inventory_mutation.construction_hash().unwrap(),
            baseline_hash,
            "application multiplicity must bind the construction fingerprint"
        );

        let mut relation_mutation = construction.clone();
        relation_mutation.ordered_families[1].canonical_relation_plan_hash[0] ^= 1;
        assert_ne!(
            relation_mutation.construction_hash().unwrap(),
            baseline_hash,
            "relation-plan identity must bind the construction fingerprint"
        );

        let public_key_index = construction
            .ordered_families
            .iter()
            .position(|family| family.compact_contract.is_some())
            .expect("one compact contract is available");
        let mut contract_mutation = construction.clone();
        contract_mutation.ordered_families[public_key_index]
            .compact_contract
            .as_mut()
            .expect("the compact contract is present")
            .canonical_contract_hash[0] ^= 1;
        assert_ne!(
            contract_mutation.construction_hash().unwrap(),
            baseline_hash,
            "compact contract identity must bind the construction fingerprint"
        );

        let mut reordered = construction.clone();
        reordered.ordered_families.swap(0, 1);
        assert_ne!(
            reordered.construction_hash().unwrap(),
            baseline_hash,
            "family order must bind the construction fingerprint"
        );
    }
}
