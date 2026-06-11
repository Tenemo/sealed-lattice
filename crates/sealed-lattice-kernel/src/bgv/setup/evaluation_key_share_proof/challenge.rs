use super::*;

pub(super) fn encode_evaluation_key_share_relation_commitments(
    key_switch_relation_commitments: &[Vec<Vec<BigInt>>],
    secret_commitment_relation_commitments: &[SetupCommitmentValue],
) -> CanonicalResult<Vec<u8>> {
    let mut encoded = Vec::new();
    for relation_commitments_by_limb in key_switch_relation_commitments {
        for relation_commitments in relation_commitments_by_limb {
            for coefficient in relation_commitments {
                write_signed_big_int_le_fixed(
                    &mut encoded,
                    coefficient,
                    EVALUATION_KEY_SHARE_RELATION_COMMITMENT_BYTE_COUNT,
                )?;
            }
        }
    }
    write_setup_commitments(&mut encoded, secret_commitment_relation_commitments);

    Ok(encoded)
}

pub(super) fn evaluation_key_share_lnp_relation_commitment_hash(
    proof_family: EvaluationKeyShareProofFamily,
    statement_hash_hex: &str,
    parameter_profile_hash_hex: &str,
    tbox_commitment_prefix_hash: &str,
    encoded_commitments: &[u8],
) -> String {
    hash512_hex(
        proof_family.commitment_hash_domain(),
        &[
            statement_hash_hex.as_bytes(),
            parameter_profile_hash_hex.as_bytes(),
            tbox_commitment_prefix_hash.as_bytes(),
            encoded_commitments,
        ],
    )
}

pub(super) fn evaluation_key_share_lnp_relation_challenge(
    proof_family: EvaluationKeyShareProofFamily,
    statement_hash_hex: &str,
    relation_commitment_hash_hex: &str,
) -> CanonicalResult<u64> {
    super::setup_proof::derive_setup_proof_scalar_challenge(
        proof_family.proof_family(),
        proof_family.scalar_challenge_domain(),
        statement_hash_hex,
        relation_commitment_hash_hex,
        EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS,
    )
}
