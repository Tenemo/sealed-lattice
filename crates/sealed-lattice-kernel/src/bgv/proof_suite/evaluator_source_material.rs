use crate::bgv::evaluator::candidate_evidence::EvaluatorCandidateInput;

use super::{CommonProofVerifierError, SuiteModulusReference, VerifiedKeySwitchComponentMaterial};

pub(super) fn material_topology_matches_selected_catalog_level(
    selected_candidate: &EvaluatorCandidateInput,
    catalog_level: usize,
    material: &VerifiedKeySwitchComponentMaterial,
) -> bool {
    let Some(active_data_prime_count) = catalog_level.checked_add(1) else {
        return false;
    };
    let Some(active_data_primes) = selected_candidate
        .data_primes
        .get(..active_data_prime_count)
    else {
        return false;
    };
    let expected_moduli = active_data_primes
        .iter()
        .chain(&selected_candidate.special_primes);
    material.topology().ordered_moduli().len()
        == active_data_primes.len() + selected_candidate.special_primes.len()
        && material
            .topology()
            .ordered_moduli()
            .iter()
            .eq(expected_moduli)
}

pub(super) fn expected_component_column_moduli(
    selected_candidate: &EvaluatorCandidateInput,
    material: &VerifiedKeySwitchComponentMaterial,
) -> Result<Box<[Option<SuiteModulusReference>]>, CommonProofVerifierError> {
    let topology = material.topology();
    let data_limb_count = topology
        .extended_limb_count()
        .checked_sub(selected_candidate.special_primes.len())
        .ok_or(CommonProofVerifierError::InvalidApplicationStatement)?;
    let mut references = Vec::new();
    references
        .try_reserve_exact(
            topology
                .trace_column_count()
                .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?,
        )
        .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?;
    for _ in 0..topology.data_block_count() {
        for data_limb_index in 0..data_limb_count {
            let modulus_reference = Some(SuiteModulusReference::data(
                u16::try_from(data_limb_index)
                    .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?,
            ));
            references.extend([modulus_reference, modulus_reference]);
        }
        for special_limb_index in 0..selected_candidate.special_primes.len() {
            let modulus_reference = Some(SuiteModulusReference::special(
                u16::try_from(special_limb_index)
                    .map_err(|_| CommonProofVerifierError::InvalidApplicationStatement)?,
            ));
            references.extend([modulus_reference, modulus_reference]);
        }
    }
    Ok(references.into_boxed_slice())
}
