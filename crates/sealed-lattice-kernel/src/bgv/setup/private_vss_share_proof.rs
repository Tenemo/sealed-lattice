use serde_json::Value;

#[cfg(test)]
use crate::hashing::{hash512_hex, to_hex};

use crate::{
    bgv::parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

use super::{
    accepted_setup::setup_context_hash,
    commitment::{SetupCommitmentValue, setup_commitment_root},
    setup_proof::{SetupProofMaterialBytes, take_verified_setup_proof_material_bytes},
    trustee_evaluation_key_proof::{
        PRIVATE_VSS_SHARE_PROOF_FAMILY, PrivateVssShareStatement, SetupProofStatement,
        SuccinctSetupProofContext, TrusteeEvaluationKeyStatement,
        decode_trustee_evaluation_key_proof_from_source,
        private_vss_share_succinct_proof_material_bytes_hash, verify_evaluation_key_share,
    },
};

#[cfg(test)]
use super::{
    commitment::SETUP_COMMITMENT_RANDOMNESS_WIDTH,
    setup_proof::SetupProofFamily,
    sharing::canonical_trustee_point,
    trustee_evaluation_key_proof::{
        TrusteeEvaluationKeyWitness, encode_trustee_evaluation_key_proof,
        prove_evaluation_key_share,
    },
};

pub(super) struct PrivateVssShareSuccinctProofVerificationInput<'a> {
    pub(super) setup_context: &'a Value,
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) private_envelope_aad_hash: &'a str,
    pub(super) source_trustee_identity: &'a str,
    pub(super) source_trustee_roster_position: u64,
    pub(super) recipient_identity: &'a str,
    pub(super) recipient_roster_position: u64,
    pub(super) source_trustee_commitment_root: &'a str,
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) ring_degree: usize,
    pub(super) coefficient_commitment_roots: &'a [String],
    pub(super) share_values: &'a [u64],
    pub(super) coefficient_commitments: &'a [SetupCommitmentValue],
    pub(super) proof_bytes_hash: &'a str,
}

#[cfg(test)]
pub(super) struct PrivateVssShareSuccinctProofWitness {
    pub(super) coefficient_messages_by_shamir_index: Vec<Vec<u64>>,
    pub(super) opening_randomness_by_shamir_index: Vec<Vec<Vec<i128>>>,
    pub(super) carry_witnesses: Vec<i128>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct PrivateVssShareSuccinctProofGenerationInput<'a> {
    pub(super) setup_context: &'a Value,
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) private_envelope_aad_hash: &'a str,
    pub(super) source_trustee_identity: &'a str,
    pub(super) source_trustee_roster_position: u64,
    pub(super) recipient_identity: &'a str,
    pub(super) recipient_roster_position: u64,
    pub(super) source_trustee_commitment_root: &'a str,
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) ring_degree: usize,
    pub(super) coefficient_commitment_roots: &'a [String],
    pub(super) share_values: &'a [u64],
    pub(super) coefficient_commitments: &'a [SetupCommitmentValue],
    pub(super) witness: &'a PrivateVssShareSuccinctProofWitness,
    pub(super) proof_randomness_seed_hex: &'a str,
}

pub(super) fn verify_private_vss_share_succinct_relation_proof(
    input: PrivateVssShareSuccinctProofVerificationInput<'_>,
) -> CanonicalResult<()> {
    validate_private_vss_share_statement_material(&input)?;
    validate_hash(input.proof_bytes_hash, "privateVssShareProofBytesHash")?;

    let proof_bytes = private_vss_share_succinct_proof_bytes_from_hash(&input)?;
    let proof_bytes_hash =
        private_vss_share_succinct_proof_material_bytes_hash(proof_bytes.as_ref())?;
    if input.proof_bytes_hash != proof_bytes_hash {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proofBytesHash must match supplied proof bytes",
        ));
    }

    let statement = private_vss_share_succinct_statement(&input)?;
    let decoded_proof =
        decode_trustee_evaluation_key_proof_from_source(&statement, proof_bytes.as_ref())?;
    verify_evaluation_key_share(&statement, &decoded_proof)?;
    Ok(())
}

fn validate_private_vss_share_statement_material(
    input: &PrivateVssShareSuccinctProofVerificationInput<'_>,
) -> CanonicalResult<()> {
    if DATA_PRIMES.get(input.rns_limb_index) != Some(&input.rns_prime) {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proof RNS limb does not match Q_share",
        ));
    }
    if input.ring_degree == 0
        || input.ring_degree > POLYNOMIAL_DEGREE
        || input.share_values.len() != input.ring_degree
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proof ring degree is outside the selected parameters",
        ));
    }
    if input
        .share_values
        .iter()
        .any(|value| *value >= input.rns_prime)
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share values must be canonical Q_share residues",
        ));
    }
    let roster = super::accepted_setup::accepted_roster_from_setup_context(input.setup_context)?;
    let expected_coefficient_count =
        usize::try_from(roster.decryption_threshold).map_err(|_| {
            invalid_private_vss_share_proof("setup decryption threshold does not fit usize")
        })?;
    if input.coefficient_commitment_roots.len() != input.coefficient_commitments.len()
        || input.coefficient_commitments.len() != expected_coefficient_count
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS share proof requires every setup Shamir coefficient commitment",
        ));
    }
    for (coefficient_index, (commitment_root, commitment)) in input
        .coefficient_commitment_roots
        .iter()
        .zip(input.coefficient_commitments.iter())
        .enumerate()
    {
        if commitment.source_rns_limb_index != input.rns_limb_index
            || commitment.shamir_coefficient_index != coefficient_index as u64
            || commitment.ring_degree != input.ring_degree
            || setup_commitment_root(commitment)? != *commitment_root
        {
            return Err(invalid_private_vss_share_proof(
                "private VSS share coefficient commitments must follow the accepted limb and Shamir coefficient order",
            ));
        }
    }

    Ok(())
}

fn private_vss_share_succinct_proof_bytes_from_hash(
    input: &PrivateVssShareSuccinctProofVerificationInput<'_>,
) -> CanonicalResult<SetupProofMaterialBytes> {
    take_verified_setup_proof_material_bytes(
        PRIVATE_VSS_SHARE_PROOF_FAMILY,
        input.proof_bytes_hash,
        "privateVssShareProofBytesHash",
        None,
    )
}

fn private_vss_share_succinct_statement(
    input: &PrivateVssShareSuccinctProofVerificationInput<'_>,
) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context = SuccinctSetupProofContext {
        setup_context_hash: setup_context_hash(input.setup_context)?,
        trustee_identity: input.source_trustee_identity.to_string(),
        trustee_roster_position: input.source_trustee_roster_position,
        binding_roots: Vec::new(),
    };
    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree: input.ring_degree,
        proof: SetupProofStatement::PrivateVssShare(PrivateVssShareStatement {
            public_matrix_seed_hash: input.public_matrix_seed_hash.to_string(),
            private_envelope_aad_hash: input.private_envelope_aad_hash.to_string(),
            source_trustee_identity: input.source_trustee_identity.to_string(),
            source_trustee_roster_position: input.source_trustee_roster_position,
            recipient_identity: input.recipient_identity.to_string(),
            recipient_roster_position: input.recipient_roster_position,
            source_trustee_commitment_root: input.source_trustee_commitment_root.to_string(),
            source_rns_limb_index: input.rns_limb_index,
            share_values: input.share_values.to_vec(),
            coefficient_commitment_roots: input.coefficient_commitment_roots.to_vec(),
            coefficient_commitments: input.coefficient_commitments.to_vec(),
        }),
    };
    statement.validate_shape()?;

    Ok(statement)
}

#[cfg(test)]
fn trustee_point_powers_i128(
    trustee_point: u64,
    coefficient_count: usize,
) -> CanonicalResult<Vec<i128>> {
    let mut powers = Vec::with_capacity(coefficient_count);
    let mut power = 1_i128;
    for _ in 0..coefficient_count {
        powers.push(power);
        power = power
            .checked_mul(i128::from(trustee_point))
            .ok_or_else(|| {
                invalid_private_vss_share_proof("private VSS trustee point power overflowed")
            })?;
    }

    Ok(powers)
}

#[cfg(test)]
fn checked_i128_sum_with_extra(values: &[i128], extra: i128) -> CanonicalResult<i128> {
    values.iter().try_fold(extra, |accumulator, value| {
        accumulator.checked_add(*value).ok_or_else(|| {
            invalid_private_vss_share_proof("private VSS lifted relation sum overflowed")
        })
    })
}

fn validate_hash(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if hash.len() == 128
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(invalid_private_vss_share_proof(format!(
        "{field_name} must be a lowercase 512-bit hex protocol hash"
    )))
}

fn invalid_private_vss_share_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
fn private_vss_share_succinct_proof_bytes_hash(proof_bytes: &[u8]) -> String {
    hash512_hex(
        SetupProofFamily::PrivateVssShare
            .proof_bytes_hash_domain()
            .expect("private VSS share proofs have a byte-hash domain"),
        &[proof_bytes],
    )
}

#[cfg(test)]
pub(super) fn private_vss_share_succinct_proof_bytes_hash_for_tests(
    input: PrivateVssShareSuccinctProofGenerationInput<'_>,
) -> CanonicalResult<String> {
    let verification_input = PrivateVssShareSuccinctProofVerificationInput {
        setup_context: input.setup_context,
        public_matrix_seed_hash: input.public_matrix_seed_hash,
        private_envelope_aad_hash: input.private_envelope_aad_hash,
        source_trustee_identity: input.source_trustee_identity,
        source_trustee_roster_position: input.source_trustee_roster_position,
        recipient_identity: input.recipient_identity,
        recipient_roster_position: input.recipient_roster_position,
        source_trustee_commitment_root: input.source_trustee_commitment_root,
        rns_limb_index: input.rns_limb_index,
        rns_prime: input.rns_prime,
        ring_degree: input.ring_degree,
        coefficient_commitment_roots: input.coefficient_commitment_roots,
        share_values: input.share_values,
        coefficient_commitments: input.coefficient_commitments,
        proof_bytes_hash: "",
    };
    validate_private_vss_share_statement_material(&verification_input)?;
    validate_private_vss_share_witness(&input)?;
    validate_private_vss_share_proof_randomness_seed(input.proof_randomness_seed_hex)?;
    let statement = private_vss_share_succinct_statement(&verification_input)?;
    let witness = TrusteeEvaluationKeyWitness::PrivateVssShare {
        coefficient_messages_by_shamir_index: input
            .witness
            .coefficient_messages_by_shamir_index
            .iter()
            .map(|messages| {
                messages
                    .iter()
                    .map(|value| {
                        i64::try_from(*value).map_err(|_| {
                            invalid_private_vss_share_proof(
                                "private VSS coefficient message does not fit i64",
                            )
                        })
                    })
                    .collect()
            })
            .collect::<CanonicalResult<Vec<Vec<i64>>>>()?,
        opening_randomness_by_shamir_index: input
            .witness
            .opening_randomness_by_shamir_index
            .iter()
            .map(|columns| {
                columns
                    .iter()
                    .map(|column| {
                        column
                            .iter()
                            .map(|value| {
                                i64::try_from(*value).map_err(|_| {
                                    invalid_private_vss_share_proof(
                                        "private VSS opening randomness does not fit i64",
                                    )
                                })
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect::<CanonicalResult<Vec<Vec<Vec<i64>>>>>()?,
        carry_witnesses: input
            .witness
            .carry_witnesses
            .iter()
            .map(|value| {
                i64::try_from(*value).map_err(|_| {
                    invalid_private_vss_share_proof("private VSS carry witness does not fit i64")
                })
            })
            .collect::<CanonicalResult<Vec<i64>>>()?,
    };
    let proof = prove_evaluation_key_share(&statement, &witness, input.proof_randomness_seed_hex)?;
    let proof_bytes = encode_trustee_evaluation_key_proof(&proof);
    let proof_bytes_hash = private_vss_share_succinct_proof_bytes_hash(&proof_bytes);
    crate::bgv::setup::retain_generated_canonical_proof_material(
        PRIVATE_VSS_SHARE_PROOF_FAMILY,
        proof_bytes_hash.clone(),
        proof_bytes,
    )?;
    Ok(proof_bytes_hash)
}

#[cfg(test)]
pub(super) fn private_vss_share_succinct_statement_hash(
    input: PrivateVssShareSuccinctProofGenerationInput<'_>,
) -> CanonicalResult<String> {
    let verification_input = PrivateVssShareSuccinctProofVerificationInput {
        setup_context: input.setup_context,
        public_matrix_seed_hash: input.public_matrix_seed_hash,
        private_envelope_aad_hash: input.private_envelope_aad_hash,
        source_trustee_identity: input.source_trustee_identity,
        source_trustee_roster_position: input.source_trustee_roster_position,
        recipient_identity: input.recipient_identity,
        recipient_roster_position: input.recipient_roster_position,
        source_trustee_commitment_root: input.source_trustee_commitment_root,
        rns_limb_index: input.rns_limb_index,
        rns_prime: input.rns_prime,
        ring_degree: input.ring_degree,
        coefficient_commitment_roots: input.coefficient_commitment_roots,
        share_values: input.share_values,
        coefficient_commitments: input.coefficient_commitments,
        proof_bytes_hash: "",
    };
    validate_private_vss_share_statement_material(&verification_input)?;
    Ok(to_hex(
        &private_vss_share_succinct_statement(&verification_input)?.statement_hash(),
    ))
}

#[cfg(test)]
fn validate_private_vss_share_witness(
    input: &PrivateVssShareSuccinctProofGenerationInput<'_>,
) -> CanonicalResult<()> {
    if input.witness.coefficient_messages_by_shamir_index.len()
        != input.coefficient_commitments.len()
        || input.witness.opening_randomness_by_shamir_index.len()
            != input.coefficient_commitments.len()
        || input.witness.carry_witnesses.len() != input.ring_degree
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS proof witness shape does not match statement material",
        ));
    }
    for (coefficient_index, (coefficient_messages, opening_randomness)) in input
        .witness
        .coefficient_messages_by_shamir_index
        .iter()
        .zip(input.witness.opening_randomness_by_shamir_index.iter())
        .enumerate()
    {
        if coefficient_messages.len() != input.ring_degree
            || coefficient_messages
                .iter()
                .any(|coefficient| *coefficient >= input.rns_prime)
            || opening_randomness.len() != SETUP_COMMITMENT_RANDOMNESS_WIDTH
            || opening_randomness
                .iter()
                .any(|column| column.len() != input.ring_degree)
        {
            return Err(invalid_private_vss_share_proof(format!(
                "private VSS proof witness for Shamir coefficient {coefficient_index} has the wrong shape"
            )));
        }
    }
    verify_private_vss_share_witness_relation(
        input.rns_prime,
        input.recipient_roster_position,
        input.share_values,
        &input.witness.coefficient_messages_by_shamir_index,
        &input.witness.carry_witnesses,
    )
}

#[cfg(test)]
fn validate_private_vss_share_proof_randomness_seed(seed_hex: &str) -> CanonicalResult<()> {
    if seed_hex.len() != 128
        || !seed_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_private_vss_share_proof(
            "private VSS proofRandomnessSeedHex must be lowercase 512-bit hex CSPRNG seed material",
        ));
    }

    Ok(())
}

#[cfg(test)]
fn verify_private_vss_share_witness_relation(
    rns_prime: u64,
    recipient_roster_position: u64,
    share_values: &[u64],
    coefficient_messages_by_shamir_index: &[Vec<u64>],
    carry_witnesses: &[i128],
) -> CanonicalResult<()> {
    let trustee_point = canonical_trustee_point(
        usize::try_from(recipient_roster_position).map_err(|_| {
            invalid_private_vss_share_proof(
                "private VSS recipient roster position does not fit usize",
            )
        })?,
        rns_prime,
    )?;
    let trustee_point_powers =
        trustee_point_powers_i128(trustee_point, coefficient_messages_by_shamir_index.len())?;
    for coefficient_index in 0..share_values.len() {
        let weighted_messages = coefficient_messages_by_shamir_index
            .iter()
            .zip(trustee_point_powers.iter())
            .map(|(coefficient_messages, trustee_point_power)| {
                trustee_point_power
                    .checked_mul(i128::from(coefficient_messages[coefficient_index]))
                    .ok_or_else(|| {
                        invalid_private_vss_share_proof(
                            "private VSS witness message relation overflowed",
                        )
                    })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        // Integer-lift relation: the q_l * carry term vanishes in the source field (q_l == 0 there) but is bound by the other commitment-modulus fields, which forces the unique integer lift; the recipient point reuses roster_position + 1.
        let carry_term = i128::from(rns_prime)
            .checked_mul(carry_witnesses[coefficient_index])
            .and_then(i128::checked_neg)
            .ok_or_else(|| {
                invalid_private_vss_share_proof("private VSS witness carry overflowed")
            })?;
        if checked_i128_sum_with_extra(&weighted_messages, carry_term)?
            != i128::from(share_values[coefficient_index])
        {
            return Err(invalid_private_vss_share_proof(format!(
                "private VSS witness relation failed at coefficient {coefficient_index}"
            )));
        }
    }

    Ok(())
}
