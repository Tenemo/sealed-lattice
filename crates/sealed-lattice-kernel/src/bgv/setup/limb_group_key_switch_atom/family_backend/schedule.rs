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
//! order. Legacy engine bytes fail the magic check, so a key-bearing statement
//! can never verify against an old-format proof.

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

use super::super::limb_group_statement::LimbGroupContext;
use super::super::negacyclic_transform::NegacyclicDomain;
use super::super::proof_field::{ProofFieldParameters, sixteen_limb_group_field_parameters};
use super::key_proof::{
    KeyFriProofParameters, LinkageStatement, LinkageWitness, prove_key_fri, verify_key_fri,
};
#[cfg(test)]
use super::material_aggregate_creation::{
    KeyGroupAggregateBinding, prove_key_group_aggregate_binding,
};
use super::proof_codec::{decode_key_proof, encode_key_proof};
use super::statement_bridge::{
    BridgeKeyMaterialInput, BridgeKeyPublicInput, BridgedKeyKind, bridge_key_material,
    bridge_key_public,
};
use crate::bgv::parameters::{DATA_PRIMES, PLAINTEXT_MODULUS};
use crate::bgv::setup::trustee_evaluation_key_proof::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, TrusteeEvaluationKeyStatement,
    TrusteeEvaluationKeyWitness, public_key_switch_sample,
};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::hashing::hash512;
#[cfg(test)]
use crate::hashing::to_hex;

const SCHEDULE_MAGIC: &[u8; 8] = b"SLKSATS2";
const SCHEDULE_SALT_DOMAIN: &str = "sealed-lattice/setup/key-switch-atom/schedule-salt";
// 80 queries at rate 1/4 give about 136 conditional classical bits under the
// CS25 accounting the setup families use; the count is soundness-set. Shared with
// the creation-side aggregate binding (`material_aggregate_creation`) and the
// accepted-setup aggregate-binding verifier so the transported openings carry the
// same soundness parameter as the atom proofs.
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

// The mask degree covering the opened evaluations at the schedule query count,
// mirroring the family benchmark's N/4 budget.
fn schedule_mask_degree(ring_degree: usize) -> usize {
    ring_degree / 4
}

// The linkage statement every key proof in the schedule binds: exactly one
// original accepted BDLOP source constant commitment.
fn linkage_statement(
    statement: &TrusteeEvaluationKeyStatement,
) -> CanonicalResult<LinkageStatement<'_>> {
    validate_key_bearing_statement(statement)?;
    let same_secret_linkage = statement.same_secret_linkage.as_ref().ok_or_else(|| {
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
        same_secret_linkage,
    })
}

// The key-bearing statement checks shared by prove and verify: at least one
// key and every kind diagonal (public-key shares stay on their own family).
fn validate_key_bearing_statement(
    statement: &TrusteeEvaluationKeyStatement,
) -> CanonicalResult<()> {
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
    Ok(())
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
    for (key_index, key) in statement.keys.iter().enumerate() {
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
    let linkage_statement = linkage_statement(statement)?;
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
                ring_degree,
                key: &statement.keys[scheduled_proof.key_index],
                scheduled: scheduled_proof,
                proof_index,
                secret: &witness.secret_coefficients,
                errors: &witness.error_coefficients_by_key[scheduled_proof.key_index],
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
    ring_degree: usize,
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
    let domain = NegacyclicDomain::new(input.parameters, input.ring_degree)?;
    let public_sample_by_digit =
        group_public_samples(input.key, input.scheduled, input.ring_degree);
    let component_b_by_digit = group_component_slice(input.key, input.scheduled);
    let bridged = bridge_key_material(
        input.parameters,
        BridgeKeyMaterialInput {
            group: &group,
            domain: &domain,
            component_b_by_digit: &component_b_by_digit,
            public_sample_by_digit: &public_sample_by_digit,
            secret_coefficients: input.secret,
            error_coefficients_by_digit: input.errors,
            kind: bridged_kind(input.key)?,
            plaintext_modulus: PLAINTEXT_MODULUS,
            group_start_limb: input.scheduled.group_start_limb,
        },
    )?;
    let mut salt_seed = key_salt_seed(input.statement_hash, input.proof_index);
    let proof = prove_key_fri(
        input.parameters,
        input.ring_degree,
        &bridged.public,
        &bridged.source,
        input.secret,
        &bridged.digits,
        Some((input.linkage_statement, input.linkage_witness)),
        input.statement_hash,
        input.proof_index as u64,
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
    let linkage_statement = linkage_statement(statement)?;
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
    let scheduled = scheduled_proofs(statement)?;
    if count != scheduled.len() {
        return Err(invalid_schedule(
            "schedule proof count must match the statement's scheduled proof count",
        ));
    }
    let mut per_proof_bytes = Vec::with_capacity(count);
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
        per_proof_bytes.push(&proof_bytes[position..end]);
        position = end;
    }
    if position != proof_bytes.len() {
        return Err(invalid_schedule("schedule proof stream has trailing bytes"));
    }

    for (chunk_start, chunk) in per_proof_bytes
        .chunks(PARALLEL_KEY_GROUP)
        .enumerate()
        .map(|(chunk, bytes)| (chunk * PARALLEL_KEY_GROUP, bytes))
    {
        let verify_at = |offset: usize, bytes: &[u8]| -> CanonicalResult<()> {
            let proof_index = chunk_start + offset;
            let scheduled_proof = &scheduled[proof_index];
            let key = &statement.keys[scheduled_proof.key_index];
            let group_primes = &DATA_PRIMES[scheduled_proof.group_start_limb
                ..scheduled_proof.group_start_limb + scheduled_proof.group_limb_count];
            let limb_group = LimbGroupContext::new(&parameters, group_primes)?;
            let domain = NegacyclicDomain::new(&parameters, ring_degree)?;
            let public_sample_by_digit = group_public_samples(key, scheduled_proof, ring_degree);
            let component_b_by_digit = group_component_slice(key, scheduled_proof);
            let (public, source) = bridge_key_public(
                &parameters,
                BridgeKeyPublicInput {
                    group: &limb_group,
                    domain: &domain,
                    component_b_by_digit: &component_b_by_digit,
                    public_sample_by_digit: &public_sample_by_digit,
                    kind: bridged_kind(key)?,
                    plaintext_modulus: PLAINTEXT_MODULUS,
                    group_start_limb: scheduled_proof.group_start_limb,
                },
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
        let results: Vec<CanonicalResult<()>> = chunk
            .par_iter()
            .enumerate()
            .map(|(offset, bytes)| verify_at(offset, bytes))
            .collect();
        #[cfg(target_arch = "wasm32")]
        let results: Vec<CanonicalResult<()>> = chunk
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

// One scheduled atom proof's published material commitment root, tagged with the
// runtime-key identity and limb span the aggregate binding indexes by. `rotation`
// is `None` for relinearization round two and `Some(rotation)` for a Galois key;
// relinearization round one has no published runtime key of its own, so it is
// omitted. Surfaced from the verified schedule container so the accepted-setup
// aggregate-binding verifier can cross-check each package `trusteeMaterialRoots`
// entry against the atom proof's own `KeyFriProof.material_root`.
pub(crate) struct KeyGroupMaterialRoot {
    pub(crate) rotation: Option<u64>,
    pub(crate) level: u64,
    pub(crate) group_start_limb: usize,
    pub(crate) group_limb_count: usize,
    pub(crate) material_root: [u8; 32],
}

// The runtime-key identity of a key, for the aggregate binding: `None` rotation
// for relinearization round two (keyed by level), `Some(rotation)` for a Galois
// key, and `None` (not runtime-bound) for round one and public-key shares. Shared
// by the material-root extractor and the `#[cfg(test)]` creation binding.
fn key_group_runtime_identity(key: &EvaluationKeyShareDescriptor) -> Option<(Option<u64>, u64)> {
    match key.kind {
        EvaluationKeyShareKind::RelinearizationRoundTwo => Some((None, key.level as u64)),
        EvaluationKeyShareKind::GaloisRotation { galois_element } => {
            Some((Some(galois_element as u64), key.level as u64))
        }
        EvaluationKeyShareKind::RelinearizationRoundOne
        | EvaluationKeyShareKind::PublicKeyShare => None,
    }
}

// Decode a verified key-bearing schedule container and surface each runtime-key
// group's atom-proof material commitment root, tagged with its identity and limb
// span. Reuses the identical strict container parse and `scheduled_proofs`
// enumeration `verify_key_bearing_trustee_evaluation_keys` uses, so the decoded
// per-key `material_root` is the exact value the verified proof published. Only
// runtime-bound key groups (relinearization round two, Galois) are returned; round
// one is skipped. This does not re-run the atom relation verification (the caller
// verifies the container separately); it strictly extracts the published roots.
//
// Fail-closed: a non-schedule container, a truncated stream, a count mismatch, or
// any per-key decode failure returns `Err`.
pub(crate) fn key_bearing_material_roots_by_key_group(
    statement: &TrusteeEvaluationKeyStatement,
    proof_bytes: &[u8],
) -> CanonicalResult<Vec<KeyGroupMaterialRoot>> {
    linkage_statement(statement)?;
    let parameters = sixteen_limb_group_field_parameters();

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
    let scheduled = scheduled_proofs(statement)?;
    if count != scheduled.len() {
        return Err(invalid_schedule(
            "schedule proof count must match the statement's scheduled proof count",
        ));
    }
    let mut material_roots = Vec::new();
    for scheduled_proof in &scheduled {
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
        let key = &statement.keys[scheduled_proof.key_index];
        if let Some((rotation, level)) = key_group_runtime_identity(key) {
            let proof = decode_key_proof(&parameters, &proof_bytes[position..end])?;
            material_roots.push(KeyGroupMaterialRoot {
                rotation,
                level,
                group_start_limb: scheduled_proof.group_start_limb,
                group_limb_count: scheduled_proof.group_limb_count,
                material_root: proof.material_root,
            });
        }
        position = end;
    }
    if position != proof_bytes.len() {
        return Err(invalid_schedule("schedule proof stream has trailing bytes"));
    }

    Ok(material_roots)
}

// One key group's creation-side aggregate binding as plain, JSON-ready data: the
// key identity (rotation and level), the group's limb span, the per-trustee
// material roots as canonical Merkle-digest hex, the per-coefficient wrap
// multiples `[digit][coeff]`, and the encoded batched opening bytes per trustee
// as hex. The accepted-setup creation path maps this directly onto the package
// aggregate-binding key-group record and the transported opening set.
#[cfg(test)]
pub(crate) struct EvaluationKeyAggregateBindingGroup {
    pub(crate) rotation: Option<u64>,
    pub(crate) level: u64,
    pub(crate) group_start_limb: usize,
    pub(crate) group_limb_count: usize,
    // The ring degree the columns and wrap rows span, taken from the statement.
    // The verifier requires this to equal `POLYNOMIAL_DEGREE`; a reduced-ring
    // development package emits its own (smaller) degree here, so the record is
    // self-consistent and the verifier fail-closes on the full-ring mismatch.
    pub(crate) ring_degree: usize,
    pub(crate) trustee_material_roots_hex: Vec<String>,
    pub(crate) wrap_multiples: Vec<Vec<i64>>,
    pub(crate) opening_bytes_hex: Vec<String>,
}

// Prove the committed-material aggregate binding for every scheduled runtime key
// group, given one trustee statement per roster position (in roster order). Each
// statement carries the trustee's transported per-key component material; the
// keys and their limb-group split are re-derived exactly as the schedule prover
// does, and only the round-two and Galois keys (which have a published runtime
// key) are bound. For each such key group this recombines every trustee's
// component material `B_col` (the same centered CRT recombination the atom proof
// commits), recomputes the published runtime-key residues as the per-limb trustee
// sum, and calls `prove_key_group_aggregate_binding`.
//
// The aggregator's material commitment is regenerated from each atom proof's own
// INITIAL salt seed (`key_salt_seed(statement_hash, proof_index)`), so a produced
// binding reproduces each atom proof's `material_root` exactly and needs no
// separate aggregator salt input. Fail-closed: any statement/shape disagreement or
// an unsolvable wrap returns `Err`.
#[cfg(test)]
pub(crate) fn prove_evaluation_key_aggregate_binding(
    statements_by_trustee: &[TrusteeEvaluationKeyStatement],
) -> CanonicalResult<Vec<EvaluationKeyAggregateBindingGroup>> {
    let roster_size = statements_by_trustee.len();
    if roster_size == 0 {
        return Err(invalid_schedule(
            "aggregate binding requires at least one trustee statement",
        ));
    }
    let parameters = sixteen_limb_group_field_parameters();
    let first_statement = &statements_by_trustee[0];
    let ring_degree = first_statement.ring_degree;

    // Every trustee's statement lists the same keys in the same schedule order
    // (they are derived from the shared package schedule), so the first trustee's
    // schedule drives the key-group enumeration and the others are checked to
    // match before their material is used.
    let scheduled = scheduled_proofs(first_statement)?;
    let mask_degree = schedule_mask_degree(ring_degree);
    let mut bindings = Vec::new();
    // The flat scheduled index is the atom proof's `proof_index`, so each atom
    // proof's initial salt seed is `key_salt_seed(statement_hash, proof_index)`.
    // Every trustee shares the schedule order (enforced by the key-identity check
    // below), so this index is the same across trustees while the statement hash
    // differs per trustee.
    for (proof_index, scheduled_proof) in scheduled.iter().enumerate() {
        let reference_key = &first_statement.keys[scheduled_proof.key_index];
        let Some((rotation, level)) = key_group_runtime_identity(reference_key) else {
            continue;
        };

        // Recombine each trustee's component material for this group, and sum the
        // raw per-limb residues into the published runtime key the atom proofs'
        // material aggregates against. Alongside, collect each trustee's atom proof
        // INITIAL salt seed for this key group, so the aggregate binding can
        // regenerate the atom's material commitment and open exactly it.
        let mut recombined_material_by_trustee = Vec::with_capacity(roster_size);
        let mut atom_initial_salt_seeds = Vec::with_capacity(roster_size);
        let mut runtime_key_by_digit: Option<Vec<Vec<Vec<u64>>>> = None;
        for statement in statements_by_trustee {
            if statement.ring_degree != ring_degree {
                return Err(invalid_schedule(
                    "aggregate binding trustee statements must share one ring degree",
                ));
            }
            let key = statement
                .keys
                .get(scheduled_proof.key_index)
                .ok_or_else(|| {
                    invalid_schedule(
                        "aggregate binding trustee statement is missing a scheduled key",
                    )
                })?;
            if key_group_runtime_identity(key) != Some((rotation, level)) {
                return Err(invalid_schedule(
                    "aggregate binding trustee statements disagree on a scheduled key identity",
                ));
            }
            let group_primes = &DATA_PRIMES[scheduled_proof.group_start_limb
                ..scheduled_proof.group_start_limb + scheduled_proof.group_limb_count];
            let group = LimbGroupContext::new(&parameters, group_primes)?;
            let domain = NegacyclicDomain::new(&parameters, ring_degree)?;
            let public_sample_by_digit = group_public_samples(key, scheduled_proof, ring_degree);
            let component_b_by_digit = group_component_slice(key, scheduled_proof);
            let (public, _source) = bridge_key_public(
                &parameters,
                BridgeKeyPublicInput {
                    group: &group,
                    domain: &domain,
                    component_b_by_digit: &component_b_by_digit,
                    public_sample_by_digit: &public_sample_by_digit,
                    kind: bridged_kind(key)?,
                    plaintext_modulus: PLAINTEXT_MODULUS,
                    group_start_limb: scheduled_proof.group_start_limb,
                },
            )?;
            let recombined_material: Vec<Vec<[u64; 13]>> = public
                .digits
                .iter()
                .map(|digit| digit.recombined_component_b.clone())
                .collect();
            accumulate_runtime_residues(
                &mut runtime_key_by_digit,
                &component_b_by_digit,
                scheduled_proof,
            )?;
            recombined_material_by_trustee.push(recombined_material);
            atom_initial_salt_seeds.push(key_salt_seed(&statement.statement_hash(), proof_index));
        }

        let runtime_key_by_digit = runtime_key_by_digit.ok_or_else(|| {
            invalid_schedule("aggregate binding runtime key aggregation had no trustee material")
        })?;
        let group_primes = &DATA_PRIMES[scheduled_proof.group_start_limb
            ..scheduled_proof.group_start_limb + scheduled_proof.group_limb_count];
        let group = LimbGroupContext::new(&parameters, group_primes)?;

        let KeyGroupAggregateBinding {
            material_roots,
            wrap_multiples,
            opening_bytes,
        } = prove_key_group_aggregate_binding(
            &parameters,
            &group,
            ring_degree,
            roster_size,
            mask_degree,
            &recombined_material_by_trustee,
            &atom_initial_salt_seeds,
            &runtime_key_by_digit,
        )?;

        bindings.push(EvaluationKeyAggregateBindingGroup {
            rotation,
            level,
            group_start_limb: scheduled_proof.group_start_limb,
            group_limb_count: scheduled_proof.group_limb_count,
            ring_degree,
            trustee_material_roots_hex: material_roots.iter().map(|root| to_hex(root)).collect(),
            wrap_multiples,
            opening_bytes_hex: opening_bytes.iter().map(|bytes| to_hex(bytes)).collect(),
        });
    }

    Ok(bindings)
}

// Accumulate one trustee's group component material into the published runtime
// key `[digit][group-limb][coeff]`, adding coefficient-wise modulo each level
// prime. The published runtime key is the per-limb trustee sum, matching the
// verifier's `accepted_key_switch_runtime_residues_by_digit` reconstruction.
#[cfg(test)]
fn accumulate_runtime_residues(
    runtime_key_by_digit: &mut Option<Vec<Vec<Vec<u64>>>>,
    component_b_by_digit: &[Vec<Vec<u64>>],
    scheduled: &ScheduledProof,
) -> CanonicalResult<()> {
    let group_primes = &DATA_PRIMES
        [scheduled.group_start_limb..scheduled.group_start_limb + scheduled.group_limb_count];
    match runtime_key_by_digit {
        None => {
            for digit in component_b_by_digit {
                if digit.len() != group_primes.len() {
                    return Err(invalid_schedule(
                        "aggregate binding component material limb count does not match the group",
                    ));
                }
            }
            *runtime_key_by_digit = Some(component_b_by_digit.to_vec());
        }
        Some(runtime_key) => {
            if runtime_key.len() != component_b_by_digit.len() {
                return Err(invalid_schedule(
                    "aggregate binding component material digit count does not match the group",
                ));
            }
            for (digit_accumulator, digit_component) in
                runtime_key.iter_mut().zip(component_b_by_digit.iter())
            {
                if digit_accumulator.len() != group_primes.len()
                    || digit_component.len() != group_primes.len()
                {
                    return Err(invalid_schedule(
                        "aggregate binding component material limb count does not match the group",
                    ));
                }
                for (limb_index, (limb_accumulator, limb_component)) in digit_accumulator
                    .iter_mut()
                    .zip(digit_component.iter())
                    .enumerate()
                {
                    let modulus = group_primes[limb_index];
                    if limb_accumulator.len() != limb_component.len() {
                        return Err(invalid_schedule(
                            "aggregate binding component material coefficient count mismatch",
                        ));
                    }
                    for (coefficient, addend) in
                        limb_accumulator.iter_mut().zip(limb_component.iter())
                    {
                        *coefficient = ((u128::from(*coefficient) + u128::from(*addend))
                            % u128::from(modulus)) as u64;
                    }
                }
            }
        }
    }
    Ok(())
}
