use super::*;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Mutex, OnceLock},
};

const TARGET_RESULT_RELEASE_VERIFICATION_ID_MAX_BYTES: usize = 128;

static TARGET_RESULT_RELEASE_SESSIONS: OnceLock<
    Mutex<BTreeMap<String, TargetResultReleaseSession>>,
> = OnceLock::new();

// A released target is consumed one-shot: once its verified-share quorum has been
// recombined into a plaintext result, the same target binding can never be
// released again, even under a fresh release verification id or a fresh quorum
// with different smudging. This in-process registry holds the canonical
// target-binding key of every target a finish has released and enforces that
// bound. Persistent consumed-state across process restarts remains an open
// obligation (see SEC-002).
static TARGET_RESULT_RELEASE_CONSUMED_TARGETS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

pub(super) struct TargetDecryptionResultReleaseBeginInput<'a> {
    pub(super) release_verification_id: &'a str,
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_accepted: &'a TargetAcceptedBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) target_share_profile: &'a TargetShareProfile,
}

pub(super) struct TargetDecryptionResultReleaseShareInput<'a> {
    pub(super) release_verification_id: &'a str,
    pub(super) target_share_proof: &'a Value,
}

pub(super) struct TargetDecryptionResultReleaseFinishInput<'a> {
    pub(super) release_verification_id: &'a str,
}

struct VerifiedTargetShareRelease {
    interpolation_point: u64,
    target_id_partials: Vec<Vec<u64>>,
    target_order_partials: Vec<Vec<u64>>,
    evidence: Value,
}

struct TargetResultReleaseSession {
    setup_binding: SetupBinding,
    target_accepted: TargetAcceptedBinding,
    target_ciphertexts: TargetCiphertextPair,
    target_share_profile: TargetShareProfile,
    seen_roster_positions: BTreeSet<u64>,
    seen_interpolation_points: BTreeSet<u64>,
    verified_shares: Vec<VerifiedTargetShareRelease>,
}

pub(super) fn begin_target_decryption_result_release(
    input: TargetDecryptionResultReleaseBeginInput<'_>,
) -> CanonicalResult<Value> {
    let release_verification_id =
        target_result_release_verification_id(input.release_verification_id)?.to_string();
    validate_target_result_release_profile(input.target_share_profile)?;
    let consumption_key = target_release_consumption_key(
        input.setup_binding,
        input.target_accepted,
        input.target_ciphertexts,
    )?;
    // Reject a target that a prior release already consumed before opening a new
    // session. This is an early check; finish holds the registry lock across the
    // recombination and is the authoritative one-shot gate.
    {
        let consumed_targets = target_result_release_consumed_targets()
            .lock()
            .map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "target result release consumed-target registry is unavailable",
                )
            })?;
        if consumed_targets.contains(&consumption_key) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "target has already been released one-shot and cannot be released again",
            ));
        }
    }
    let sessions = target_result_release_sessions();
    let mut sessions = sessions.lock().map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target result release session store is unavailable",
        )
    })?;
    if sessions.contains_key(&release_verification_id) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target result release verification id is already active",
        ));
    }
    sessions.insert(
        release_verification_id.clone(),
        TargetResultReleaseSession {
            setup_binding: input.setup_binding.clone(),
            target_accepted: input.target_accepted.clone(),
            target_ciphertexts: input.target_ciphertexts.clone(),
            target_share_profile: input.target_share_profile.clone(),
            seen_roster_positions: BTreeSet::new(),
            seen_interpolation_points: BTreeSet::new(),
            verified_shares: Vec::with_capacity(input.target_share_profile.decryption_share_quorum),
        },
    );

    Ok(json!({
        "operation": "beginBgvTargetDecryptionResultRelease",
        "releaseVerificationId": release_verification_id,
        "setupPackageHash": input.setup_binding.setup_package_hash,
        "targetAcceptedRecordHash": input.target_accepted.target_accepted_record_hash,
        "targetDecryptionCiphertextHash": input.target_ciphertexts.target_ciphertext_hash,
        "targetShareProfileHash": input.target_share_profile.hash,
        "requiredShareCount": input.target_share_profile.decryption_share_quorum,
    }))
}

pub(super) fn absorb_target_decryption_result_release_share(
    input: TargetDecryptionResultReleaseShareInput<'_>,
) -> CanonicalResult<Value> {
    let release_verification_id =
        target_result_release_verification_id(input.release_verification_id)?.to_string();
    let sessions = target_result_release_sessions();
    let mut sessions = sessions.lock().map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target result release session store is unavailable",
        )
    })?;
    let absorb_result = {
        let session = sessions.get_mut(&release_verification_id).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "target result release verification id is not active",
            )
        })?;
        absorb_target_result_release_share(session, input.target_share_proof)
    };
    match absorb_result {
        Ok(response) => Ok(response),
        Err(error) => {
            sessions.remove(&release_verification_id);
            Err(error)
        }
    }
}

pub(super) fn finish_target_decryption_result_release(
    input: TargetDecryptionResultReleaseFinishInput<'_>,
) -> CanonicalResult<Value> {
    let release_verification_id =
        target_result_release_verification_id(input.release_verification_id)?.to_string();
    let sessions = target_result_release_sessions();
    let mut sessions = sessions.lock().map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target result release session store is unavailable",
        )
    })?;
    let session = sessions.remove(&release_verification_id).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target result release verification id is not active",
        )
    })?;
    drop(sessions);
    validate_target_result_release_quorum(
        &session.target_share_profile,
        session.verified_shares.len(),
    )?;

    let consumption_key = target_release_consumption_key(
        &session.setup_binding,
        &session.target_accepted,
        &session.target_ciphertexts,
    )?;
    // Hold the consumed-target registry across the check, the recombination, and
    // the insert so the one-shot property is race-free: two finishes that both
    // reached quorum for the same target serialize here, the first recombines and
    // consumes the target, and the second is refused before a second plaintext is
    // revealed. A recombination failure returns without consuming, so a failed
    // release does not burn the target.
    let mut consumed_targets = target_result_release_consumed_targets()
        .lock()
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "target result release consumed-target registry is unavailable",
            )
        })?;
    if consumed_targets.contains(&consumption_key) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target has already been released one-shot and cannot be released again",
        ));
    }
    let release = release_verified_target_shares(
        &session.setup_binding,
        &session.target_accepted,
        &session.target_ciphertexts,
        &session.target_share_profile,
        session.verified_shares,
        "finishBgvTargetDecryptionResultRelease",
    )?;
    consumed_targets.insert(consumption_key);

    Ok(release)
}

fn absorb_target_result_release_share(
    session: &mut TargetResultReleaseSession,
    target_share_proof: &Value,
) -> CanonicalResult<Value> {
    if session.verified_shares.len() >= session.target_share_profile.decryption_share_quorum {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target result release session already has the required share quorum",
        ));
    }
    let verified_share = verify_target_share_release_entry(
        &session.setup_binding,
        &session.target_accepted,
        &session.target_ciphertexts,
        &session.target_share_profile,
        target_share_proof,
    )?;
    let roster_position = unsigned_at_path(&verified_share.evidence, &["rosterPosition"])?;
    if !session.seen_roster_positions.insert(roster_position) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target result release share quorum repeats a trustee",
        ));
    }
    if !session
        .seen_interpolation_points
        .insert(verified_share.interpolation_point)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target result release share quorum repeats an interpolation point",
        ));
    }
    let proof_material_root =
        hash_at_path(&verified_share.evidence, &["proofMaterialRoot"])?.to_string();
    let target_decryption_share_hash =
        hash_at_path(&verified_share.evidence, &["targetDecryptionShareHash"])?.to_string();
    session.verified_shares.push(verified_share);

    Ok(json!({
        "operation": "absorbBgvTargetDecryptionResultReleaseShare",
        "absorbedShareCount": session.verified_shares.len(),
        "requiredShareCount": session.target_share_profile.decryption_share_quorum,
        "rosterPosition": roster_position,
        "targetDecryptionShareHash": target_decryption_share_hash,
        "proofMaterialRoot": proof_material_root,
    }))
}

fn validate_target_result_release_quorum(
    target_share_profile: &TargetShareProfile,
    share_count: usize,
) -> CanonicalResult<()> {
    validate_target_result_release_profile(target_share_profile)?;
    if share_count != target_share_profile.decryption_share_quorum {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target result release requires exactly the target decryption share quorum",
        ));
    }

    Ok(())
}

fn validate_target_result_release_profile(
    target_share_profile: &TargetShareProfile,
) -> CanonicalResult<()> {
    if target_share_profile.decryption_share_quorum
        < target_share_profile.minimum_shares_for_interpolation
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target result release quorum is below the interpolation threshold",
        ));
    }

    Ok(())
}

fn target_result_release_sessions() -> &'static Mutex<BTreeMap<String, TargetResultReleaseSession>>
{
    TARGET_RESULT_RELEASE_SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn target_result_release_consumed_targets() -> &'static Mutex<BTreeSet<String>> {
    TARGET_RESULT_RELEASE_CONSUMED_TARGETS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

// The canonical one-shot consumption key for a target release binds the supplied
// setup-package hash, caller-supplied target-binding hash, and exact target
// ciphertext-pair hash. These hashes are structurally checked here; this key does
// not authenticate accepted board or state capabilities. Repeating the same
// supplied bindings collides on this key. The target-share profile is deliberately
// excluded, so changing a still-valid (minimum, quorum) profile cannot mint a
// fresh key and escape the one-shot bound.
fn target_release_consumption_key(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "BgvTargetDecryptionResultReleaseConsumptionKey",
        "setupPackageHash": setup_binding.setup_package_hash,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetDecryptionCiphertextHash": target_ciphertexts.target_ciphertext_hash,
    }))
}

fn target_result_release_verification_id(value: &str) -> CanonicalResult<&str> {
    if value.is_empty()
        || value.len() > TARGET_RESULT_RELEASE_VERIFICATION_ID_MAX_BYTES
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_:.".contains(character))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target result release verification id must be a short ASCII identifier",
        ));
    }

    Ok(value)
}

fn release_verified_target_shares(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    verified_shares: Vec<VerifiedTargetShareRelease>,
    operation: &str,
) -> CanonicalResult<Value> {
    let interpolation_points = verified_shares
        .iter()
        .map(|share| share.interpolation_point)
        .collect::<Vec<_>>();
    let target_id_partials_by_share = verified_shares
        .iter()
        .map(|share| share.target_id_partials.as_slice())
        .collect::<Vec<_>>();
    let target_order_partials_by_share = verified_shares
        .iter()
        .map(|share| share.target_order_partials.as_slice())
        .collect::<Vec<_>>();
    let target_id_slots = release_target_role_slots(
        &target_ciphertexts.target_id,
        &interpolation_points,
        &target_id_partials_by_share,
    )?;
    let target_order_slots = release_target_role_slots(
        &target_ciphertexts.target_order,
        &interpolation_points,
        &target_order_partials_by_share,
    )?;
    let target_id_by_option =
        packed_target_option_values(&target_id_slots, target_ciphertexts.top_count)?;
    let target_order_by_option =
        packed_target_option_values(&target_order_slots, target_ciphertexts.top_count)?;
    let share_evidence = verified_shares
        .into_iter()
        .map(|share| share.evidence)
        .collect::<Vec<_>>();
    let result_preimage = json!({
        "objectType": "BgvTargetDecryptionResult",
        "setupPackageHash": setup_binding.setup_package_hash,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetDecryptionCiphertextHash": target_ciphertexts.target_ciphertext_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "topCount": target_ciphertexts.top_count,
        "targetIdByOption": target_id_by_option,
        "targetOrderByOption": target_order_by_option,
        "shareEvidence": share_evidence,
    });
    let target_result_hash = derive_canonical_object_hash(&result_preimage)?;

    Ok(json!({
        "operation": operation,
        "targetResultHash": target_result_hash,
        "targetIdByOption": result_preimage["targetIdByOption"].clone(),
        "targetOrderByOption": result_preimage["targetOrderByOption"].clone(),
        "topCount": target_ciphertexts.top_count,
        "shareEvidence": result_preimage["shareEvidence"].clone(),
    }))
}

fn verify_target_share_release_entry(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    share_proof: &Value,
) -> CanonicalResult<VerifiedTargetShareRelease> {
    let target_decryption_share = value_at_path(share_proof, &["targetDecryptionShare"])?;
    let proof_statement = value_at_path(share_proof, &["proofStatement"])?;
    let proof_material = value_at_path(share_proof, &["proofMaterial"])?;
    let trustee_identity = string_at_path(proof_statement, &["trusteeIdentity"])?;
    let participant = setup_binding
        .participants
        .iter()
        .find(|candidate| candidate.trustee_identity == trustee_identity)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target result release share proof trustee is not part of the setup roster",
            )
        })?;
    verify_target_decryption_share_proof_material(
        TargetDecryptionShareProofMaterialVerificationInput {
            setup_binding,
            target_accepted,
            target_ciphertexts,
            target_share_profile,
            participant,
            target_decryption_share,
            proof_statement,
            proof_material,
        },
    )?;
    let payload = value_at_path(target_decryption_share, &["sharePayload"])?;
    let target_id_partials =
        read_partial_limb_set(payload, "targetId", target_ciphertexts.target_id.level)?;
    let target_order_partials = read_partial_limb_set(
        payload,
        "targetOrder",
        target_ciphertexts.target_order.level,
    )?;

    Ok(VerifiedTargetShareRelease {
        interpolation_point: participant.interpolation_point,
        target_id_partials,
        target_order_partials,
        evidence: json!({
            "trusteeIdentity": participant.trustee_identity,
            "rosterPosition": participant.roster_position,
            "interpolationPoint": participant.interpolation_point,
            "targetDecryptionShareHash": hash_at_path(target_decryption_share, &["targetDecryptionShareHash"])?,
            "proofStatementRoot": hash_at_path(proof_statement, &["proofStatementRoot"])?,
            "proofMaterialRoot": hash_at_path(proof_material, &["proofMaterialRoot"])?,
        }),
    })
}

pub(super) fn release_target_role_slots(
    ciphertext: &Ciphertext,
    interpolation_points: &[u64],
    partials_by_share: &[&[Vec<u64>]],
) -> CanonicalResult<Vec<u64>> {
    let active_limb_count = ciphertext.level + 1;
    if partials_by_share.len() != interpolation_points.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target result release partial count must match interpolation points",
        ));
    }
    let mut accumulator = ciphertext.components[0].clone();
    if accumulator.len() != active_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target result release ciphertext accumulator has the wrong active limb count",
        ));
    }

    for rns_limb_index in 0..active_limb_count {
        let modulus = DATA_PRIMES[rns_limb_index];
        let lagrange_weights = lagrange_weights_at_zero(interpolation_points, modulus)?;
        for coefficient_index in 0..POLYNOMIAL_DEGREE {
            let mut interpolated_partial = 0_u64;
            for (share_index, share_partials) in partials_by_share.iter().enumerate() {
                if share_partials.len() != active_limb_count {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target result release share partials have the wrong active limb count",
                    ));
                }
                let share_limb = share_partials.get(rns_limb_index).ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target result release share partials are missing an active limb",
                    )
                })?;
                if share_limb.len() != POLYNOMIAL_DEGREE {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target result release share partial limb has the wrong coefficient count",
                    ));
                }
                let weighted_partial = mul_mod_fast(
                    share_limb[coefficient_index],
                    lagrange_weights[share_index],
                    modulus,
                );
                interpolated_partial =
                    add_mod_fast(interpolated_partial, weighted_partial, modulus);
            }
            accumulator[rns_limb_index][coefficient_index] = add_mod_fast(
                accumulator[rns_limb_index][coefficient_index],
                interpolated_partial,
                modulus,
            );
        }
    }

    let coefficients = decryption_accumulator_to_coefficients(ciphertext, &accumulator)?;
    forward_negacyclic_ntt(&coefficients, PLAINTEXT_MODULUS)
}

fn lagrange_weights_at_zero(
    interpolation_points: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    interpolation_points
        .iter()
        .enumerate()
        .map(|(selected_index, selected_point)| {
            let selected_point = *selected_point % modulus;
            let mut numerator = 1_u64;
            let mut denominator = 1_u64;
            for (other_index, other_point) in interpolation_points.iter().enumerate() {
                if other_index == selected_index {
                    continue;
                }
                let other_point = *other_point % modulus;
                numerator = mul_mod(numerator, sub_mod(0, other_point, modulus)?, modulus)?;
                denominator = mul_mod(
                    denominator,
                    sub_mod(selected_point, other_point, modulus)?,
                    modulus,
                )?;
            }
            mul_mod(numerator, inverse_mod(denominator, modulus)?, modulus)
        })
        .collect()
}

pub(super) fn packed_target_option_values(
    slots: &[u64],
    top_count: usize,
) -> CanonicalResult<Vec<u64>> {
    if top_count == 0 || top_count > MAXIMUM_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target result topCount is outside the supported option count",
        ));
    }
    if slots.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target result slots must match the selected ring degree",
        ));
    }

    (0..MAXIMUM_OPTION_COUNT)
        .map(|option_index| {
            slots
                .get(packed_score_slot(option_index))
                .copied()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target result packed option slot is outside the selected ring",
                    )
                })
        })
        .collect()
}
