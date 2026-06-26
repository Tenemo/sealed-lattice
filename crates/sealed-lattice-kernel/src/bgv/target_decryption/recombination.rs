use std::collections::BTreeSet;

use super::*;

const TARGET_DECRYPTION_PLAINTEXT_COEFFICIENT_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-plaintext-coefficients-v1";
const TARGET_DECRYPTION_PLAINTEXT_SLOT_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/target-decryption-plaintext-slots-v1";

pub(super) struct TargetDecryptionShareProofBundle<'a> {
    pub(super) target_decryption_share: &'a Value,
    pub(super) proof_statement: &'a Value,
    pub(super) proof_material: &'a Value,
}

pub(super) struct TargetDecryptionRecombinationInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_accepted: &'a TargetAcceptedBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) target_share_profile: &'a TargetShareProfile,
    pub(super) proof_bundles: Vec<TargetDecryptionShareProofBundle<'a>>,
}

struct VerifiedTargetDecryptionShare {
    trustee_identity: String,
    roster_position: usize,
    interpolation_point: u64,
    target_decryption_share_hash: String,
    target_share_proof_statement_root: String,
    proof_material_root: String,
    target_id_partials_by_limb: Vec<Vec<u64>>,
    target_order_partials_by_limb: Vec<Vec<u64>>,
}

struct RecombinedTargetPlaintext {
    coefficient_hash: String,
    slot_hash: String,
    option_values: Vec<u64>,
}

pub(super) fn verify_and_recombine_target_decryption_shares(
    input: TargetDecryptionRecombinationInput<'_>,
) -> CanonicalResult<Value> {
    if input.proof_bundles.len() != input.target_share_profile.minimum_shares_for_interpolation {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target recombination requires exactly the interpolation quorum of proof-backed shares",
        ));
    }

    let mut verified_shares = input
        .proof_bundles
        .iter()
        .map(|proof_bundle| verify_target_decryption_share_for_recombination(&input, proof_bundle))
        .collect::<CanonicalResult<Vec<_>>>()?;
    verified_shares.sort_by_key(|share| (share.interpolation_point, share.roster_position));
    validate_unique_recombination_points(&verified_shares)?;

    let target_id_plaintext = recombine_target_role(
        &input.target_ciphertexts.target_id,
        &verified_shares,
        |share| &share.target_id_partials_by_limb,
    )?;
    let target_order_plaintext = recombine_target_role(
        &input.target_ciphertexts.target_order,
        &verified_shares,
        |share| &share.target_order_partials_by_limb,
    )?;

    let share_inputs = verified_shares
        .iter()
        .map(|share| {
            json!({
                "trusteeIdentity": share.trustee_identity,
                "rosterPosition": share.roster_position,
                "interpolationPoint": share.interpolation_point,
                "targetDecryptionShareHash": share.target_decryption_share_hash,
                "targetShareProofStatementRoot": share.target_share_proof_statement_root,
                "proofMaterialRoot": share.proof_material_root,
            })
        })
        .collect::<Vec<_>>();
    let mut result = json!({
        "ok": true,
        "operation": "verifyAndRecombineBgvTargetDecryptionShares",
        "setupPackageHash": input.setup_binding.setup_package_hash,
        "ceremonyId": input.setup_binding.ceremony_id,
        "electionManifestHash": input.setup_binding.election_manifest_hash,
        "targetAcceptedRecordHash": input.target_accepted.target_accepted_record_hash,
        "targetContextHash": input.target_accepted.target_context_hash,
        "targetCiphertextHash": input.target_accepted.target_ciphertext_hash,
        "targetDecryptionCiphertextHash": input.target_ciphertexts.target_ciphertext_hash,
        "targetCiphertextBindingHash": input.target_ciphertexts.target_ciphertext_binding_hash,
        "targetIdRoot": input.target_ciphertexts.target_id_root,
        "targetOrderRoot": input.target_ciphertexts.target_order_root,
        "targetShareProfileHash": input.target_share_profile.hash,
        "targetBasisHash": input.target_accepted.target_basis_hash,
        "minimumSharesForInterpolation": input.target_share_profile.minimum_shares_for_interpolation,
        "decryptionThreshold": input.target_share_profile.decryption_threshold,
        "shareCount": share_inputs.len(),
        "activeRnsLimbCount": input.target_ciphertexts.target_id.level + 1,
        "ringDegree": POLYNOMIAL_DEGREE,
        "plaintextModulus": PLAINTEXT_MODULUS,
        "optionCount": MAXIMUM_OPTION_COUNT,
        "topCount": input.target_ciphertexts.top_count,
        "shareInputs": share_inputs,
        "targetIdPlaintextCoefficientHash512": target_id_plaintext.coefficient_hash,
        "targetIdPlaintextSlotHash512": target_id_plaintext.slot_hash,
        "targetIdOptionValues": target_id_plaintext.option_values,
        "targetOrderPlaintextCoefficientHash512": target_order_plaintext.coefficient_hash,
        "targetOrderPlaintextSlotHash512": target_order_plaintext.slot_hash,
        "targetOrderOptionValues": target_order_plaintext.option_values,
    });
    result["targetDecryptionResultHash"] =
        json!(derive_protocol_hash("TargetDecryptionResultHash", &result)?);

    Ok(result)
}

fn verify_target_decryption_share_for_recombination(
    input: &TargetDecryptionRecombinationInput<'_>,
    proof_bundle: &TargetDecryptionShareProofBundle<'_>,
) -> CanonicalResult<VerifiedTargetDecryptionShare> {
    let trustee_identity = string_at_path(proof_bundle.proof_statement, &["trusteeIdentity"])?;
    let participant = input
        .setup_binding
        .participants
        .iter()
        .find(|candidate| candidate.trustee_identity == trustee_identity)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target recombination proof statement trustee is not part of the setup roster",
            )
        })?;
    let verification = verify_target_decryption_share_proof_material(
        TargetDecryptionShareProofMaterialVerificationInput {
            setup_binding: input.setup_binding,
            target_accepted: input.target_accepted,
            target_ciphertexts: input.target_ciphertexts,
            target_share_profile: input.target_share_profile,
            participant,
            target_decryption_share: proof_bundle.target_decryption_share,
            proof_statement: proof_bundle.proof_statement,
            proof_material: proof_bundle.proof_material,
        },
    )?;
    read_partial_decryption_share(
        proof_bundle.target_decryption_share,
        input.setup_binding,
        input.target_accepted,
        input.target_ciphertexts,
        input.target_share_profile,
    )?;
    let payload = value_at_path(proof_bundle.target_decryption_share, &["sharePayload"])?;

    Ok(VerifiedTargetDecryptionShare {
        trustee_identity: participant.trustee_identity.clone(),
        roster_position: participant.roster_position,
        interpolation_point: participant.interpolation_point,
        target_decryption_share_hash: hash_at_path(
            proof_bundle.target_decryption_share,
            &["targetDecryptionShareHash"],
        )?
        .to_string(),
        target_share_proof_statement_root: hash_at_path(
            proof_bundle.proof_statement,
            &["proofStatementRoot"],
        )?
        .to_string(),
        proof_material_root: hash_at_path(&verification, &["proofMaterialRoot"])?.to_string(),
        target_id_partials_by_limb: read_partial_limb_set(
            payload,
            "targetId",
            input.target_ciphertexts.target_id.level,
        )?,
        target_order_partials_by_limb: read_partial_limb_set(
            payload,
            "targetOrder",
            input.target_ciphertexts.target_order.level,
        )?,
    })
}

fn validate_unique_recombination_points(
    verified_shares: &[VerifiedTargetDecryptionShare],
) -> CanonicalResult<()> {
    let mut roster_positions = BTreeSet::new();
    let mut interpolation_points = BTreeSet::new();
    for share in verified_shares {
        if share.interpolation_point == 0 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "target recombination share interpolation points must be non-zero",
            ));
        }
        if !roster_positions.insert(share.roster_position) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "target recombination shares must not repeat a roster position",
            ));
        }
        if !interpolation_points.insert(share.interpolation_point) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "target recombination shares must not repeat an interpolation point",
            ));
        }
    }

    Ok(())
}

fn recombine_target_role(
    ciphertext: &Ciphertext,
    verified_shares: &[VerifiedTargetDecryptionShare],
    partials_for_share: fn(&VerifiedTargetDecryptionShare) -> &[Vec<u64>],
) -> CanonicalResult<RecombinedTargetPlaintext> {
    if ciphertext.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target recombination requires two-component target ciphertexts",
        ));
    }
    let mut decryption_accumulator = ciphertext.components[0].clone();
    let interpolation_points = verified_shares
        .iter()
        .map(|share| share.interpolation_point)
        .collect::<Vec<_>>();
    for (rns_limb_index, modulus) in ciphertext.primes().iter().copied().enumerate() {
        let interpolation_weights = lagrange_weights_at_zero(&interpolation_points, modulus)?;
        for (share_index, share) in verified_shares.iter().enumerate() {
            let partials_by_limb = partials_for_share(share);
            let partial_limb = partials_by_limb.get(rns_limb_index).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target recombination share is missing an active limb",
                )
            })?;
            if partial_limb.len() != POLYNOMIAL_DEGREE {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target recombination share limb has the wrong coefficient count",
                ));
            }
            let interpolation_weight = interpolation_weights[share_index];
            for (accumulator_coefficient, partial_coefficient) in decryption_accumulator
                [rns_limb_index]
                .iter_mut()
                .zip(partial_limb.iter())
            {
                let weighted_partial =
                    mul_mod_fast(*partial_coefficient, interpolation_weight, modulus);
                *accumulator_coefficient =
                    add_mod_fast(*accumulator_coefficient, weighted_partial, modulus);
            }
        }
    }

    let coefficients = decryption_accumulator_to_coefficients(ciphertext, &decryption_accumulator)?;
    let slots = forward_negacyclic_ntt(&coefficients, PLAINTEXT_MODULUS)?;

    Ok(RecombinedTargetPlaintext {
        coefficient_hash: coefficient_vector_hash512(
            &coefficients,
            TARGET_DECRYPTION_PLAINTEXT_COEFFICIENT_HASH_DOMAIN,
        ),
        slot_hash: coefficient_vector_hash512(&slots, TARGET_DECRYPTION_PLAINTEXT_SLOT_HASH_DOMAIN),
        option_values: target_option_values_from_slots(&slots)?,
    })
}

fn target_option_values_from_slots(slots: &[u64]) -> CanonicalResult<Vec<u64>> {
    (0..MAXIMUM_OPTION_COUNT)
        .map(|option_index| {
            slots
                .get(packed_score_slot(option_index))
                .copied()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target plaintext slot vector does not cover every supported option",
                    )
                })
        })
        .collect()
}

fn lagrange_weights_at_zero(
    interpolation_points: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    interpolation_points
        .iter()
        .enumerate()
        .map(|(participant_index, selected_point)| {
            let selected_point = *selected_point % modulus;
            let mut numerator = 1_u64;
            let mut denominator = 1_u64;
            for (other_participant_index, other_point) in interpolation_points.iter().enumerate() {
                if other_participant_index == participant_index {
                    continue;
                }
                let other_point = *other_point % modulus;
                if selected_point == other_point {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        "target recombination interpolation points must be distinct modulo every active prime",
                    ));
                }
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
