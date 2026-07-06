//! Per-trustee schedule proving and verification for key-bearing trustee
//! evaluation-key statements: one atom family proof per scheduled key, each
//! transcript-bound to the statement hash and the key's schedule index, with
//! the same-secret linkage opening the statement's first bridge target
//! constant commitment (the verified bridge proves cross-limb consistency, so
//! one opened commitment binds every key's relation secret to the anchor, and
//! all keys share one secret transitively).
//!
//! The container byte format is strict and self-describing: the schedule
//! magic, the key count, then one length-framed atom proof per key in schedule
//! order. Legacy engine bytes fail the magic check, so a key-bearing statement
//! can never verify against an old-format proof.

use rayon::prelude::*;

use super::super::limb_group_statement::LimbGroupContext;
use super::super::negacyclic_transform::NegacyclicDomain;
use super::super::proof_field::{ProofFieldParameters, sixteen_limb_group_field_parameters};
use super::key_proof::{
    KeyFriProofParameters, LinkageStatement, LinkageWitness, prove_key_fri, verify_key_fri,
};
use super::proof_codec::{decode_key_proof, encode_key_proof};
use super::statement_bridge::{
    BridgeKeyMaterialInput, BridgedKeyKind, bridge_key_material, bridge_key_public,
};
use crate::bgv::parameters::{DATA_PRIMES, PLAINTEXT_MODULUS};
use crate::bgv::setup::trustee_evaluation_key_proof::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, SameSecretBridgeStatement,
    TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness, public_key_switch_sample,
};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::hashing::hash512;

const SCHEDULE_MAGIC: &[u8; 8] = b"SLKSATS1";
const SCHEDULE_SALT_DOMAIN: &str = "sealed-lattice/setup/key-switch-atom/schedule-salt-v1";
// 80 queries at rate 1/4 give about 136 conditional classical bits under the
// CS25 accounting the setup families use; the count is soundness-set.
const SCHEDULE_QUERY_COUNT: usize = 80;
// Keys prove independently; bounding the concurrent set keeps the peak
// working set at a few streamed provers rather than the whole schedule.
const PARALLEL_KEY_GROUP: usize = 4;

fn invalid_schedule(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

// The mask degree covering the opened evaluations at the schedule query count,
// mirroring the family benchmark's N/4 budget.
fn schedule_mask_degree(ring_degree: usize) -> usize {
    ring_degree / 4
}

// The linkage statement every key proof in the schedule binds: the FIRST
// bridge target constant commitment (position 0 in the bridge's target list,
// which is also the sampler's limb index for that commitment).
fn linkage_statement_from_bridge(
    bridge: &SameSecretBridgeStatement,
) -> CanonicalResult<LinkageStatement<'_>> {
    let commitment = bridge
        .target_constant_commitments
        .first()
        .ok_or_else(|| invalid_schedule("the same-secret bridge carries no target commitments"))?;
    let source_message_modulus = *bridge
        .target_rns_primes
        .first()
        .ok_or_else(|| invalid_schedule("the same-secret bridge carries no target primes"))?;
    Ok(LinkageStatement {
        public_matrix_seed_hash: &bridge.public_matrix_seed_hash,
        source_rns_limb_index: 0,
        source_message_modulus,
        coordinates_by_commitment_modulus: &commitment.coordinates_by_commitment_modulus,
    })
}

// The key-bearing statement checks shared by prove and verify: at least one
// key, every kind diagonal (public-key shares stay on their own family), and
// the fail-closed same-secret bridge anchor present.
fn key_bearing_bridge(
    statement: &TrusteeEvaluationKeyStatement,
) -> CanonicalResult<&SameSecretBridgeStatement> {
    if statement.keys.is_empty() {
        return Err(invalid_schedule(
            "a key-bearing trustee evaluation-key statement lists at least one key",
        ));
    }
    if statement
        .keys
        .iter()
        .any(|key| !key.kind.has_diagonal_source())
    {
        return Err(invalid_schedule(
            "public-key share descriptors do not belong to the key-bearing schedule",
        ));
    }
    statement.same_secret_bridge.as_ref().ok_or_else(|| {
        invalid_schedule(
            "a key-bearing trustee evaluation-key statement requires the same-secret bridge anchor",
        )
    })
}

// Whether a statement routes to the atom schedule backend (any diagonal-source
// key) rather than the shared succinct engine.
pub(crate) fn statement_is_key_bearing(statement: &TrusteeEvaluationKeyStatement) -> bool {
    statement
        .keys
        .iter()
        .any(|key| key.kind.has_diagonal_source())
}

// The deterministic per-key salt stream seed, bound to the statement and the
// key's schedule position.
fn key_salt_seed(statement_hash: &[u8; 64], key_index: usize) -> u64 {
    let digest = hash512(
        SCHEDULE_SALT_DOMAIN,
        &[statement_hash, &(key_index as u64).to_le_bytes()],
    );
    u64::from_le_bytes(digest[..8].try_into().expect("eight bytes"))
}

// The per-limb public key-switch samples for one key digit, derived exactly as
// the transported material was generated.
fn digit_public_samples(
    key: &EvaluationKeyShareDescriptor,
    digit_index: usize,
    limb_count: usize,
    ring_degree: usize,
) -> Vec<Vec<u64>> {
    (0..limb_count)
        .map(|limb_index| {
            public_key_switch_sample(
                &key.key_switch_domain,
                &key.key_switch_seed_hex,
                digit_index,
                DATA_PRIMES[limb_index],
                ring_degree,
            )
        })
        .collect()
}

struct KeyGeometry {
    limb_count: usize,
    public_sample_by_digit: Vec<Vec<Vec<u64>>>,
}

fn key_geometry(
    key: &EvaluationKeyShareDescriptor,
    ring_degree: usize,
) -> CanonicalResult<KeyGeometry> {
    let limb_count = key
        .level
        .checked_add(1)
        .filter(|count| *count <= DATA_PRIMES.len())
        .ok_or_else(|| invalid_schedule("key level is outside the data prime basis"))?;
    if key.component_b_by_digit.len() != limb_count {
        return Err(invalid_schedule(
            "key digit count must match its level's limb count",
        ));
    }
    let public_sample_by_digit = (0..limb_count)
        .map(|digit_index| digit_public_samples(key, digit_index, limb_count, ring_degree))
        .collect();
    Ok(KeyGeometry {
        limb_count,
        public_sample_by_digit,
    })
}

fn bridged_kind<'a>(key: &'a EvaluationKeyShareDescriptor) -> CanonicalResult<BridgedKeyKind<'a>> {
    Ok(match key.kind {
        EvaluationKeyShareKind::RelinearizationRoundOne => BridgedKeyKind::RelinearizationRoundOne,
        EvaluationKeyShareKind::GaloisRotation { galois_element } => {
            BridgedKeyKind::Galois { galois_element }
        }
        EvaluationKeyShareKind::RelinearizationRoundTwo => {
            BridgedKeyKind::RelinearizationRoundTwo {
                aggregate_residues_by_digit: &key.round_one_aggregate_diagonal,
            }
        }
        EvaluationKeyShareKind::PublicKeyShare => {
            return Err(invalid_schedule(
                "public-key share descriptors do not belong to the key-bearing schedule",
            ));
        }
    })
}

// Prove every scheduled key with the atom family backend, returning the
// container bytes.
pub(crate) fn prove_key_bearing_trustee_evaluation_keys(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
) -> CanonicalResult<Vec<u8>> {
    let bridge = key_bearing_bridge(statement)?;
    let linkage_statement = linkage_statement_from_bridge(bridge)?;
    if witness.error_coefficients_by_key.len() != statement.keys.len() {
        return Err(invalid_schedule(
            "witness error vectors must cover every scheduled key",
        ));
    }
    let linkage_randomness = witness.opening_randomness_by_limb.first().ok_or_else(|| {
        invalid_schedule("the linkage witness requires the first target's opening randomness")
    })?;
    let linkage_witness = LinkageWitness {
        negative_indicator: &witness.negative_indicator_coefficients,
        randomness_by_column: linkage_randomness,
    };
    let parameters = sixteen_limb_group_field_parameters();
    let statement_hash = statement.statement_hash();
    let ring_degree = statement.ring_degree;
    let proof_parameters = KeyFriProofParameters {
        query_count: SCHEDULE_QUERY_COUNT,
        mask_degree: schedule_mask_degree(ring_degree),
    };

    let mut per_key_bytes: Vec<Vec<u8>> = Vec::with_capacity(statement.keys.len());
    for (group_start, key_group) in statement
        .keys
        .chunks(PARALLEL_KEY_GROUP)
        .enumerate()
        .map(|(group, keys)| (group * PARALLEL_KEY_GROUP, keys))
    {
        let group_results: Vec<CanonicalResult<Vec<u8>>> = key_group
            .par_iter()
            .enumerate()
            .map(|(offset, key)| {
                let key_index = group_start + offset;
                prove_one_key(ProveOneKey {
                    parameters: &parameters,
                    statement_hash: &statement_hash,
                    ring_degree,
                    key,
                    key_index,
                    secret: &witness.secret_coefficients,
                    errors: &witness.error_coefficients_by_key[key_index],
                    linkage_statement: &linkage_statement,
                    linkage_witness: &linkage_witness,
                    proof_parameters: &proof_parameters,
                })
            })
            .collect();
        for result in group_results {
            per_key_bytes.push(result?);
        }
    }

    let mut container = SCHEDULE_MAGIC.to_vec();
    let count = u32::try_from(per_key_bytes.len())
        .map_err(|_| invalid_schedule("schedule key count exceeds u32"))?;
    container.extend_from_slice(&count.to_le_bytes());
    for bytes in &per_key_bytes {
        let length =
            u32::try_from(bytes.len()).map_err(|_| invalid_schedule("proof length exceeds u32"))?;
        container.extend_from_slice(&length.to_le_bytes());
        container.extend_from_slice(bytes);
    }
    Ok(container)
}

struct ProveOneKey<'a, const LIMB_COUNT: usize> {
    parameters: &'a ProofFieldParameters<LIMB_COUNT>,
    statement_hash: &'a [u8; 64],
    ring_degree: usize,
    key: &'a EvaluationKeyShareDescriptor,
    key_index: usize,
    secret: &'a [i64],
    errors: &'a [Vec<i64>],
    linkage_statement: &'a LinkageStatement<'a>,
    linkage_witness: &'a LinkageWitness<'a>,
    proof_parameters: &'a KeyFriProofParameters,
}

fn prove_one_key<const LIMB_COUNT: usize>(
    input: ProveOneKey<'_, LIMB_COUNT>,
) -> CanonicalResult<Vec<u8>> {
    let geometry = key_geometry(input.key, input.ring_degree)?;
    let group = LimbGroupContext::new(input.parameters, &DATA_PRIMES[..geometry.limb_count])?;
    let domain = NegacyclicDomain::new(input.parameters, input.ring_degree)?;
    let bridged = bridge_key_material(
        input.parameters,
        BridgeKeyMaterialInput {
            group: &group,
            domain: &domain,
            component_b_by_digit: &input.key.component_b_by_digit,
            public_sample_by_digit: &geometry.public_sample_by_digit,
            secret_coefficients: input.secret,
            error_coefficients_by_digit: input.errors,
            kind: bridged_kind(input.key)?,
            plaintext_modulus: PLAINTEXT_MODULUS,
        },
    )?;
    let mut salt_seed = key_salt_seed(input.statement_hash, input.key_index);
    let proof = prove_key_fri(
        input.parameters,
        input.ring_degree,
        &bridged.public,
        &bridged.source,
        input.secret,
        &bridged.digits,
        Some((input.linkage_statement, input.linkage_witness)),
        input.statement_hash,
        input.key_index as u64,
        input.proof_parameters,
        &mut salt_seed,
    )?;
    encode_key_proof(&proof)
}

// Verify a key-bearing statement's container bytes: strict container shape,
// then one atom verification per key against the statement-derived public
// inputs, the shared linkage statement, and the statement/index binding.
pub(crate) fn verify_key_bearing_trustee_evaluation_keys(
    statement: &TrusteeEvaluationKeyStatement,
    proof_bytes: &[u8],
) -> CanonicalResult<()> {
    let bridge = key_bearing_bridge(statement)?;
    let linkage_statement = linkage_statement_from_bridge(bridge)?;
    let parameters = sixteen_limb_group_field_parameters();
    let statement_hash = statement.statement_hash();
    let ring_degree = statement.ring_degree;
    let proof_parameters = KeyFriProofParameters {
        query_count: SCHEDULE_QUERY_COUNT,
        mask_degree: schedule_mask_degree(ring_degree),
    };

    if proof_bytes.len() < SCHEDULE_MAGIC.len() + 4
        || &proof_bytes[..SCHEDULE_MAGIC.len()] != SCHEDULE_MAGIC
    {
        return Err(invalid_schedule(
            "key-bearing trustee evaluation-key proof bytes are not schedule-format",
        ));
    }
    let mut position = SCHEDULE_MAGIC.len();
    let count = u32::from_le_bytes(
        proof_bytes[position..position + 4]
            .try_into()
            .expect("four bytes"),
    ) as usize;
    position += 4;
    if count != statement.keys.len() {
        return Err(invalid_schedule(
            "schedule proof count must match the statement's key count",
        ));
    }
    let mut per_key_bytes = Vec::with_capacity(count);
    for _ in 0..count {
        if position + 4 > proof_bytes.len() {
            return Err(invalid_schedule("schedule proof stream is truncated"));
        }
        let length = u32::from_le_bytes(
            proof_bytes[position..position + 4]
                .try_into()
                .expect("four bytes"),
        ) as usize;
        position += 4;
        let end = position
            .checked_add(length)
            .ok_or_else(|| invalid_schedule("schedule proof length overflows"))?;
        if end > proof_bytes.len() {
            return Err(invalid_schedule("schedule proof stream is truncated"));
        }
        per_key_bytes.push(&proof_bytes[position..end]);
        position = end;
    }
    if position != proof_bytes.len() {
        return Err(invalid_schedule("schedule proof stream has trailing bytes"));
    }

    for (group_start, group) in per_key_bytes
        .chunks(PARALLEL_KEY_GROUP)
        .enumerate()
        .map(|(group, bytes)| (group * PARALLEL_KEY_GROUP, bytes))
    {
        let results: Vec<CanonicalResult<()>> = group
            .par_iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let key_index = group_start + offset;
                let key = &statement.keys[key_index];
                let geometry = key_geometry(key, ring_degree)?;
                let limb_group =
                    LimbGroupContext::new(&parameters, &DATA_PRIMES[..geometry.limb_count])?;
                let domain = NegacyclicDomain::new(&parameters, ring_degree)?;
                let (public, source) = bridge_key_public(
                    &parameters,
                    &limb_group,
                    &domain,
                    &key.component_b_by_digit,
                    &geometry.public_sample_by_digit,
                    bridged_kind(key)?,
                    PLAINTEXT_MODULUS,
                )?;
                let proof = decode_key_proof(&parameters, bytes)?;
                let accepted = verify_key_fri(
                    &parameters,
                    ring_degree,
                    &public,
                    &source,
                    &proof,
                    Some(&linkage_statement),
                    &statement_hash,
                    key_index as u64,
                    &proof_parameters,
                )?;
                if !accepted {
                    return Err(invalid_schedule(
                        "a scheduled trustee evaluation-key atom proof was rejected",
                    ));
                }
                Ok(())
            })
            .collect();
        for result in results {
            result?;
        }
    }
    Ok(())
}
