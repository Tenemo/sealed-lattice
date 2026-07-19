use super::*;

pub(in super::super) fn setup_commitment_root(
    commitment: &SetupCommitmentValue,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&setup_commitment_root_payload(commitment))
}

fn setup_commitment_root_payload(commitment: &SetupCommitmentValue) -> Value {
    json!({
        "objectType": "SetupCommitment",
        "sourceRnsLimbIndex": commitment.source_rns_limb_index,
        "shamirCoefficientIndex": commitment.shamir_coefficient_index,
        "ringDegree": commitment.ring_degree,
        "commitmentLimbs": commitment.limbs.iter().map(|limb| {
            json!({
                "rowCoefficientHash512": limb.rows.iter().map(|row| {
                    coefficient_vector_hash512(
                        row,
                        "sealed-lattice-bdlop-commitment/row-coefficients",
                    )
                }).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>()
    })
}
