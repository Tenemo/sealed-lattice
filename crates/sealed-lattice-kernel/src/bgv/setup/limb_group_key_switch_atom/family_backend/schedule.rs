//! Per-trustee schedule proving and verification for key-bearing trustee
//! evaluation-key statements: one atom family proof per scheduled key limb
//! group (keys wider than the group capacity split into consecutive groups),
//! each transcript-bound to the statement hash and its schedule position, with
//! the same-secret linkage opening one original accepted VSS source constant
//! commitment. Every scheduled key opens that exact canonical source commitment
//! to the same short secret used by its key-switch relation.
//!
//! The container byte format is strict and self-describing: the schedule
//! magic, the key count, then one length-framed atom proof per key in schedule
//! order. Bytes from any other proof format fail the magic check, so a
//! key-bearing statement can verify only against this schedule container.

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

use super::super::limb_group_statement::LimbGroupContext;
use super::super::negacyclic_transform::NegacyclicDomain;
use super::super::proof_field::{ProofFieldParameters, sixteen_limb_group_field_parameters};
use super::key_proof::{
    KeyFriProofParameters, LinkageStatement, LinkageWitness, key_fri_proof_decoding_shape,
    prove_key_fri_with_negacyclic_domain, verify_key_fri_with_negacyclic_domain,
};
use super::private_randomness::PrivateProofRandomness;
use super::proof_codec::{decode_key_proof, encode_key_proof};
use super::statement_bridge::{
    BridgeKeyMaterialInput, BridgeKeyPublicInput, BridgedKeyKind, bridge_key_material,
    bridge_key_public,
};
use crate::bgv::parameters::{DATA_PRIMES, PLAINTEXT_MODULUS};
use crate::bgv::setup::ProofByteSource;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, TrusteeEvaluationKeyStatement,
    TrusteeEvaluationKeyWitness, public_key_switch_sample,
};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

const SCHEDULE_MAGIC: &[u8; 8] = b"SLKSATS2";
const SCHEDULE_RANDOMNESS_DOMAIN: &str =
    "sealed-lattice/setup/key-switch-atom/schedule-private-randomness/v1";
pub(crate) const SCHEDULE_QUERY_COUNT: usize = 80;
// Keys prove independently; bounding the concurrent set keeps the peak
// working set at a few streamed provers rather than the whole schedule.
const PARALLEL_KEY_GROUP: usize = 4;
// The proof field hosts at most sixteen data primes per limb group (the
// sixteen-limb group field modulus bounds the group product); wider keys
// split into consecutive groups with one atom proof per group.
const LIMB_GROUP_CAPACITY: usize = 16;

fn invalid_schedule(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}
// Per-column mask degree for scheduled proofs; N/4 stays inside the quotient
// degree budget.
fn schedule_mask_degree(ring_degree: usize) -> usize {
    ring_degree / 4
}

// The linkage statement every key proof in the schedule binds: exactly one
// original accepted BDLOP source constant commitment.
fn linkage_statement(
    statement: &TrusteeEvaluationKeyStatement,
) -> CanonicalResult<LinkageStatement<'_>> {
    validate_key_bearing_statement(statement)?;
    let same_secret_linkage = statement.same_secret_linkage().ok_or_else(|| {
        invalid_schedule(
            "a key-bearing trustee evaluation-key statement requires one accepted BDLOP source constant commitment",
        )
    })?;
    if same_secret_linkage.commitments.len() != 1 {
        return Err(invalid_schedule(
            "the key-bearing BDLOP linkage must carry exactly one source constant commitment",
        ));
    }
    Ok(LinkageStatement {
        linkage: same_secret_linkage,
    })
}

// The key-bearing statement checks shared by prove and verify: at least one
// key and every kind diagonal (public-key shares stay on their own family).
fn validate_key_bearing_statement(
    statement: &TrusteeEvaluationKeyStatement,
) -> CanonicalResult<()> {
    if statement.keys().is_empty() {
        return Err(invalid_schedule(
            "a key-bearing trustee evaluation-key statement lists at least one key",
        ));
    }
    if statement
        .keys()
        .iter()
        .any(|key| !key.kind.has_diagonal_source())
    {
        return Err(invalid_schedule(
            "public-key share descriptors do not belong to the key-bearing schedule",
        ));
    }
    Ok(())
}

// Whether a statement routes to the atom schedule backend (any diagonal-source
// key) rather than the shared succinct engine.
pub(crate) fn statement_is_key_bearing(statement: &TrusteeEvaluationKeyStatement) -> bool {
    statement
        .keys()
        .iter()
        .any(|key| key.kind.has_diagonal_source())
}

// Each scheduled proof gets a distinct private mask/salt stream. The caller's
// fresh seed is already bound to the statement, trustee, and setup context.
fn key_private_randomness(
    statement_hash: &[u8; 64],
    proof_randomness_seed_hex: &str,
    key_index: usize,
) -> PrivateProofRandomness {
    PrivateProofRandomness::new(
        SCHEDULE_RANDOMNESS_DOMAIN,
        &[
            proof_randomness_seed_hex.as_bytes(),
            statement_hash,
            &(key_index as u64).to_le_bytes(),
        ],
    )
}

// One scheduled atom proof: a key and one of its consecutive limb groups.
// The order is deterministic from the statement (keys in statement order,
// groups ascending), so prover and verifier derive the identical schedule.
struct ScheduledProof {
    key_index: usize,
    group_start_limb: usize,
    group_limb_count: usize,
}

fn scheduled_proofs(
    statement: &TrusteeEvaluationKeyStatement,
) -> CanonicalResult<Vec<ScheduledProof>> {
    let mut proofs = Vec::new();
    for (key_index, key) in statement.keys().iter().enumerate() {
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
        let mut group_start_limb = 0;
        while group_start_limb < limb_count {
            let group_limb_count = LIMB_GROUP_CAPACITY.min(limb_count - group_start_limb);
            proofs.push(ScheduledProof {
                key_index,
                group_start_limb,
                group_limb_count,
            });
            group_start_limb += group_limb_count;
        }
    }
    Ok(proofs)
}

// The group's public key-switch samples: for every digit, the samples at the
// group's limbs, derived exactly as the transported material was generated.
fn group_public_samples(
    key: &EvaluationKeyShareDescriptor,
    scheduled: &ScheduledProof,
    ring_degree: usize,
) -> Vec<Vec<Vec<u64>>> {
    let digit_count = key.component_b_by_digit.len();
    (0..digit_count)
        .map(|digit_index| {
            (scheduled.group_start_limb..scheduled.group_start_limb + scheduled.group_limb_count)
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
        })
        .collect()
}

// The group's transported component slice: every digit, the group's limbs.
fn group_component_slice(
    key: &EvaluationKeyShareDescriptor,
    scheduled: &ScheduledProof,
) -> Vec<Vec<Vec<u64>>> {
    key.component_b_by_digit
        .iter()
        .map(|limb_vectors| {
            limb_vectors[scheduled.group_start_limb
                ..scheduled.group_start_limb + scheduled.group_limb_count]
                .to_vec()
        })
        .collect()
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
    })
}

// Prove every scheduled key with the atom family backend, returning the
// container bytes.
pub(crate) fn prove_key_bearing_trustee_evaluation_keys(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<Vec<u8>> {
    let linkage_statement = linkage_statement(statement)?;
    if witness.error_coefficients_by_key().len() != statement.keys().len() {
        return Err(invalid_schedule(
            "witness error vectors must cover every scheduled key",
        ));
    }
    let linkage_randomness = witness
        .opening_randomness_by_source_limb_and_commitment_limb()
        .first()
        .ok_or_else(|| {
            invalid_schedule("the linkage witness requires the first target's opening randomness")
        })?;
    let linkage_witness = LinkageWitness {
        negative_indicator: witness.negative_indicator_coefficients(),
        randomness_by_commitment_limb: linkage_randomness,
    };
    let parameters = sixteen_limb_group_field_parameters();
    let statement_hash = statement.statement_hash();
    let ring_degree = statement.ring_degree;
    // These immutable tables depend only on the field and ring degree. Share
    // them across every scheduled atom instead of rebuilding and retaining two
    // copies per concurrently active bridge/prover.
    let negacyclic_domain = NegacyclicDomain::new(&parameters, ring_degree)?;
    let proof_parameters = KeyFriProofParameters {
        query_count: SCHEDULE_QUERY_COUNT,
        mask_degree: schedule_mask_degree(ring_degree),
    };

    let scheduled = scheduled_proofs(statement)?;
    let mut per_proof_bytes: Vec<Vec<u8>> = Vec::with_capacity(scheduled.len());
    for (chunk_start, chunk) in scheduled
        .chunks(PARALLEL_KEY_GROUP)
        .enumerate()
        .map(|(chunk, proofs)| (chunk * PARALLEL_KEY_GROUP, proofs))
    {
        let prove_at = |offset: usize, scheduled_proof: &ScheduledProof| {
            let proof_index = chunk_start + offset;
            prove_one_key(ProveOneKey {
                parameters: &parameters,
                statement_hash: &statement_hash,
                proof_randomness_seed_hex,
                ring_degree,
                negacyclic_domain: &negacyclic_domain,
                key: &statement.keys()[scheduled_proof.key_index],
                scheduled: scheduled_proof,
                proof_index,
                secret: witness.secret_coefficients(),
                errors: &witness.error_coefficients_by_key()[scheduled_proof.key_index],
                linkage_statement: &linkage_statement,
                linkage_witness: &linkage_witness,
                proof_parameters: &proof_parameters,
            })
        };
        #[cfg(not(target_arch = "wasm32"))]
        let chunk_results: Vec<CanonicalResult<Vec<u8>>> = chunk
            .par_iter()
            .enumerate()
            .map(|(offset, scheduled_proof)| prove_at(offset, scheduled_proof))
            .collect();
        #[cfg(target_arch = "wasm32")]
        let chunk_results: Vec<CanonicalResult<Vec<u8>>> = chunk
            .iter()
            .enumerate()
            .map(|(offset, scheduled_proof)| prove_at(offset, scheduled_proof))
            .collect();
        for result in chunk_results {
            per_proof_bytes.push(result?);
        }
    }

    let mut container = SCHEDULE_MAGIC.to_vec();
    let count = u32::try_from(per_proof_bytes.len())
        .map_err(|_| invalid_schedule("schedule proof count exceeds u32"))?;
    container.extend_from_slice(&count.to_le_bytes());
    for bytes in &per_proof_bytes {
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
    proof_randomness_seed_hex: &'a str,
    ring_degree: usize,
    negacyclic_domain: &'a NegacyclicDomain<'a, LIMB_COUNT>,
    key: &'a EvaluationKeyShareDescriptor,
    scheduled: &'a ScheduledProof,
    proof_index: usize,
    secret: &'a [i64],
    errors: &'a [Vec<i64>],
    linkage_statement: &'a LinkageStatement<'a>,
    linkage_witness: &'a LinkageWitness<'a>,
    proof_parameters: &'a KeyFriProofParameters,
}

fn prove_one_key<const LIMB_COUNT: usize>(
    input: ProveOneKey<'_, LIMB_COUNT>,
) -> CanonicalResult<Vec<u8>> {
    let group_primes = &DATA_PRIMES[input.scheduled.group_start_limb
        ..input.scheduled.group_start_limb + input.scheduled.group_limb_count];
    let group = LimbGroupContext::new(input.parameters, group_primes)?;
    let public_sample_by_digit =
        group_public_samples(input.key, input.scheduled, input.ring_degree);
    let component_b_by_digit = group_component_slice(input.key, input.scheduled);
    let bridged = bridge_key_material(
        input.parameters,
        BridgeKeyMaterialInput {
            group: &group,
            domain: input.negacyclic_domain,
            component_b_by_digit: &component_b_by_digit,
            public_sample_by_digit: &public_sample_by_digit,
            secret_coefficients: input.secret,
            error_coefficients_by_digit: input.errors,
            kind: bridged_kind(input.key)?,
            plaintext_modulus: PLAINTEXT_MODULUS,
            group_start_limb: input.scheduled.group_start_limb,
        },
    )?;
    let mut private_randomness = key_private_randomness(
        input.statement_hash,
        input.proof_randomness_seed_hex,
        input.proof_index,
    );
    let proof = prove_key_fri_with_negacyclic_domain(
        input.parameters,
        input.ring_degree,
        input.negacyclic_domain,
        &bridged.public,
        &bridged.source,
        input.secret,
        &bridged.digits,
        Some((input.linkage_statement, input.linkage_witness)),
        input.statement_hash,
        input.proof_index as u64,
        input.proof_parameters,
        &mut private_randomness,
    )?;
    encode_key_proof(&proof)
}

// Verify a key-bearing statement's container bytes: strict container shape,
// then one atom verification per key against the statement-derived public
// inputs, the shared linkage statement, and the statement/index binding.
fn read_schedule_u32(
    proof_bytes: &(impl ProofByteSource + ?Sized),
    offset: usize,
) -> CanonicalResult<u32> {
    let mut encoded = [0_u8; 4];
    if !proof_bytes.copy_bytes(offset, &mut encoded) {
        return Err(invalid_schedule("schedule proof stream is truncated"));
    }
    Ok(u32::from_le_bytes(encoded))
}

fn copy_schedule_proof_bytes(
    proof_bytes: &(impl ProofByteSource + ?Sized),
    offset: usize,
    byte_length: usize,
) -> CanonicalResult<Vec<u8>> {
    let mut encoded = vec![0_u8; byte_length];
    if !proof_bytes.copy_bytes(offset, &mut encoded) {
        return Err(invalid_schedule("schedule proof stream is truncated"));
    }
    Ok(encoded)
}

pub(crate) fn verify_key_bearing_trustee_evaluation_keys(
    statement: &TrusteeEvaluationKeyStatement,
    proof_bytes: &(impl ProofByteSource + ?Sized),
) -> CanonicalResult<()> {
    let linkage_statement = linkage_statement(statement)?;
    let parameters = sixteen_limb_group_field_parameters();
    let statement_hash = statement.statement_hash();
    let ring_degree = statement.ring_degree;
    // Public bridging and proof verification use the same immutable domain.
    let negacyclic_domain = NegacyclicDomain::new(&parameters, ring_degree)?;
    let proof_parameters = KeyFriProofParameters {
        query_count: SCHEDULE_QUERY_COUNT,
        mask_degree: schedule_mask_degree(ring_degree),
    };

    let mut observed_magic = [0_u8; 8];
    if proof_bytes.byte_length() < SCHEDULE_MAGIC.len() + 4
        || !proof_bytes.copy_bytes(0, &mut observed_magic)
        || &observed_magic != SCHEDULE_MAGIC
    {
        return Err(invalid_schedule(
            "key-bearing trustee evaluation-key proof bytes are not schedule-format",
        ));
    }
    let mut position = SCHEDULE_MAGIC.len();
    let count = read_schedule_u32(proof_bytes, position)? as usize;
    position += 4;
    let scheduled = scheduled_proofs(statement)?;
    if count != scheduled.len() {
        return Err(invalid_schedule(
            "schedule proof count must match the statement's scheduled proof count",
        ));
    }
    let mut per_proof_ranges = Vec::with_capacity(count);
    for _ in 0..count {
        if position + 4 > proof_bytes.byte_length() {
            return Err(invalid_schedule("schedule proof stream is truncated"));
        }
        let length = read_schedule_u32(proof_bytes, position)? as usize;
        position += 4;
        let end = position
            .checked_add(length)
            .ok_or_else(|| invalid_schedule("schedule proof length overflows"))?;
        if end > proof_bytes.byte_length() {
            return Err(invalid_schedule("schedule proof stream is truncated"));
        }
        per_proof_ranges.push((position, length));
        position = end;
    }
    if position != proof_bytes.byte_length() {
        return Err(invalid_schedule("schedule proof stream has trailing bytes"));
    }

    for (chunk_start, chunk) in per_proof_ranges
        .chunks(PARALLEL_KEY_GROUP)
        .enumerate()
        .map(|(chunk_index, ranges)| (chunk_index * PARALLEL_KEY_GROUP, ranges))
    {
        let chunk_proof_bytes = chunk
            .iter()
            .map(|(offset, byte_length)| {
                copy_schedule_proof_bytes(proof_bytes, *offset, *byte_length)
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let verify_at = |offset: usize, bytes: &[u8]| -> CanonicalResult<()> {
            let proof_index = chunk_start + offset;
            let scheduled_proof = &scheduled[proof_index];
            let key = &statement.keys()[scheduled_proof.key_index];
            let group_primes = &DATA_PRIMES[scheduled_proof.group_start_limb
                ..scheduled_proof.group_start_limb + scheduled_proof.group_limb_count];
            let limb_group = LimbGroupContext::new(&parameters, group_primes)?;
            let public_sample_by_digit = group_public_samples(key, scheduled_proof, ring_degree);
            let component_b_by_digit = group_component_slice(key, scheduled_proof);
            let (public, source) = bridge_key_public(
                &parameters,
                BridgeKeyPublicInput {
                    group: &limb_group,
                    domain: &negacyclic_domain,
                    component_b_by_digit: &component_b_by_digit,
                    public_sample_by_digit: &public_sample_by_digit,
                    kind: bridged_kind(key)?,
                    plaintext_modulus: PLAINTEXT_MODULUS,
                    group_start_limb: scheduled_proof.group_start_limb,
                },
            )?;
            let decoding_shape = key_fri_proof_decoding_shape(
                ring_degree,
                public.digits.len(),
                true,
                proof_parameters.query_count,
            )?;
            let proof = decode_key_proof(&parameters, bytes, &decoding_shape)?;
            let accepted = verify_key_fri_with_negacyclic_domain(
                &parameters,
                ring_degree,
                &negacyclic_domain,
                &public,
                &source,
                &proof,
                Some(&linkage_statement),
                &statement_hash,
                proof_index as u64,
                &proof_parameters,
            )?;
            if !accepted {
                return Err(invalid_schedule(
                    "a scheduled trustee evaluation-key atom proof was rejected",
                ));
            }
            Ok(())
        };
        #[cfg(not(target_arch = "wasm32"))]
        let results: Vec<CanonicalResult<()>> = chunk_proof_bytes
            .par_iter()
            .enumerate()
            .map(|(offset, bytes)| verify_at(offset, bytes))
            .collect();
        #[cfg(target_arch = "wasm32")]
        let results: Vec<CanonicalResult<()>> = chunk_proof_bytes
            .iter()
            .enumerate()
            .map(|(offset, bytes)| verify_at(offset, bytes))
            .collect();
        for result in results {
            result?;
        }
    }
    Ok(())
}
