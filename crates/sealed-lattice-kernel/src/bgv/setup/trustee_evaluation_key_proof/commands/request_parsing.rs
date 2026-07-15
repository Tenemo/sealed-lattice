use super::super::invalid_succinct_setup_proof;
use super::super::relation::{
    EvaluationKeyShareDescriptor, SameSecretBridgeStatement, SameSecretLinkageStatement,
    SameSecretLinkageWitness, SetupProofStatement, SuccinctSetupProofContext,
    SuccinctSetupProofFamilyShape, TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness,
    VssCommittedMaterialWitness, VssShareLinkageItem, VssShareLinkageStatement,
};
use super::VssPublicCommandCommitmentExpectation;
use super::decoding::{
    read_i64_array, read_i64_matrix, read_i64_matrix2, read_string, read_string_array, read_u64,
};
use super::target_decryption_parsing::{
    key_descriptor_from_value, vss_share_linkage_commitment_from_value,
};
use crate::bgv::parameters::DATA_PRIMES;
use crate::bgv::setup::commitment::parse_setup_commitment_full_value;
use crate::encoding::CanonicalResult;
use crate::hashing::derive_canonical_object_hash;
use serde_json::Value;

fn same_secret_bridge_fields_from_value(
    statement_value: &Value,
    context: &SuccinctSetupProofContext,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
) -> CanonicalResult<SameSecretBridgeStatement> {
    let target_constant_commitment_values = statement_value
        .get("targetConstantCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(
                "sameSecretBridge.targetConstantCommitments must be an array",
            )
        })?;
    if target_constant_commitment_values.len() != DATA_PRIMES.len() {
        return Err(invalid_succinct_setup_proof(
            "sameSecretBridge must contain one target commitment for every Q_share limb",
        ));
    }
    let target_constant_commitment_roots = target_constant_commitment_values
        .iter()
        .map(derive_canonical_object_hash)
        .collect::<CanonicalResult<Vec<_>>>()?;
    let target_constant_commitments = target_constant_commitment_values
        .iter()
        .zip(target_constant_commitment_roots.iter())
        .zip(DATA_PRIMES.iter())
        .enumerate()
        .map(
            |(target_rns_limb_index, ((value, expected_commitment_root), target_rns_prime))| {
                vss_share_linkage_commitment_from_value(
                    value,
                    VssPublicCommandCommitmentExpectation {
                        field_name: format!("targetConstantCommitments.{target_rns_limb_index}"),
                        root: expected_commitment_root,
                        role: "coefficient",
                        rns_limb_index: target_rns_limb_index,
                        rns_prime: *target_rns_prime,
                        ring_degree,
                    },
                )
            },
        )
        .collect::<CanonicalResult<Vec<_>>>()?;
    Ok(SameSecretBridgeStatement {
        public_matrix_seed_hash: public_matrix_seed_hash.to_string(),
        source_trustee_identity: context.trustee_identity.clone(),
        source_trustee_roster_position: context.trustee_roster_position,
        bridge_rns_primes: DATA_PRIMES.to_vec(),
        target_constant_commitment_roots,
        target_constant_commitments,
    })
}

// The same-secret bridge targets on a public-key share statement request: the
// committed material the atom schedule's linkage connects.
fn same_secret_bridge_from_statement_request(
    request: &Value,
    context: &SuccinctSetupProofContext,
    ring_degree: usize,
) -> CanonicalResult<SameSecretBridgeStatement> {
    let statement_value = request
        .get("sameSecretBridge")
        .ok_or_else(|| invalid_succinct_setup_proof("sameSecretBridge must be present"))?;
    let public_matrix_seed_hash = read_string(statement_value, "publicMatrixSeedHash")?;
    same_secret_bridge_fields_from_value(
        statement_value,
        context,
        public_matrix_seed_hash,
        ring_degree,
    )
}

fn same_secret_linkage_from_statement_request(
    request: &Value,
) -> CanonicalResult<SameSecretLinkageStatement> {
    let linkage_value = request
        .get("sameSecretLinkage")
        .ok_or_else(|| invalid_succinct_setup_proof("sameSecretLinkage must be present"))?;
    let commitment_values = linkage_value
        .get("commitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof("sameSecretLinkage.commitments must be an array")
        })?;
    let commitments = commitment_values
        .iter()
        .map(parse_setup_commitment_full_value)
        .collect::<CanonicalResult<Vec<_>>>()?;
    Ok(SameSecretLinkageStatement {
        public_matrix_seed_hash: read_string(linkage_value, "publicMatrixSeedHash")?.to_string(),
        commitments,
    })
}

pub(in crate::bgv::setup::trustee_evaluation_key_proof) fn statement_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context_value = request
        .get("context")
        .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
    let ring_degree = usize::try_from(read_u64(request, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let key_values = request
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_succinct_setup_proof("keys must be an array"))?;
    let keys = key_values
        .iter()
        .map(|key_value| key_descriptor_from_value(key_value, request))
        .collect::<CanonicalResult<Vec<_>>>()?;
    // The key kinds decide the family, and the family decides which labeled
    // binding roots the context must carry.
    let shape = SuccinctSetupProofFamilyShape::from_key_kinds(
        &keys.iter().map(|key| key.kind).collect::<Vec<_>>(),
    )?;
    let context = proof_context_from_value(context_value, shape)?;
    let proof = match shape {
        SuccinctSetupProofFamilyShape::PublicKeyShare => {
            let [key] = <Vec<EvaluationKeyShareDescriptor> as TryInto<
                [EvaluationKeyShareDescriptor; 1],
            >>::try_into(keys)
            .map_err(|_| {
                invalid_succinct_setup_proof(
                    "the public-key share statement requires exactly one key descriptor",
                )
            })?;
            SetupProofStatement::PublicKeyShare {
                key,
                same_secret_bridge: same_secret_bridge_from_statement_request(
                    request,
                    &context,
                    ring_degree,
                )?,
            }
        }
        SuccinctSetupProofFamilyShape::TrusteeEvaluationKey => {
            SetupProofStatement::TrusteeEvaluationKey {
                keys,
                same_secret_linkage: same_secret_linkage_from_statement_request(request)?,
            }
        }
        _ => {
            return Err(invalid_succinct_setup_proof(
                "key descriptors selected a non-key-bearing proof family",
            ));
        }
    };
    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        proof,
    };
    statement.validate_shape()?;

    Ok(statement)
}

pub(super) fn proof_context_from_value(
    context_value: &Value,
    shape: SuccinctSetupProofFamilyShape,
) -> CanonicalResult<SuccinctSetupProofContext> {
    Ok(SuccinctSetupProofContext {
        setup_context_hash: read_string(context_value, "setupContextHash")?.to_string(),
        trustee_identity: read_string(context_value, "trusteeIdentity")?.to_string(),
        trustee_roster_position: read_u64(context_value, "trusteeRosterPosition")?,
        binding_roots: shape
            .binding_labels()
            .iter()
            .map(|label| Ok(read_string(context_value, label)?.to_string()))
            .collect::<CanonicalResult<Vec<_>>>()?,
    })
}

pub(super) fn vss_share_linkage_statement_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context_value = request
        .get("context")
        .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
    let ring_degree = usize::try_from(read_u64(request, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let statement_value = request
        .get("vssShareLinkage")
        .ok_or_else(|| invalid_succinct_setup_proof("vssShareLinkage must be present"))?;
    let context = proof_context_from_value(
        context_value,
        SuccinctSetupProofFamilyShape::VssShareLinkage,
    )?;
    let public_matrix_seed_hash = read_string(statement_value, "publicMatrixSeedHash")?.to_string();
    let is_threshold_aggregate = match statement_value.get("isThresholdAggregate") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => {
            return Err(invalid_succinct_setup_proof(
                "vssShareLinkage.isThresholdAggregate must be a boolean",
            ));
        }
    };
    let primary_item = vss_share_linkage_item_from_value(
        statement_value,
        "vssShareLinkage",
        ring_degree,
        is_threshold_aggregate,
    )?;
    let additional_linkage_items = match statement_value.get("additionalLinkageItems") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(item_index, item_value)| {
                vss_share_linkage_item_from_value(
                    item_value,
                    &format!("vssShareLinkage.additionalLinkageItems.{item_index}"),
                    ring_degree,
                    is_threshold_aggregate,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?,
        Some(_) => {
            return Err(invalid_succinct_setup_proof(
                "vssShareLinkage.additionalLinkageItems must be an array",
            ));
        }
    };

    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        proof: SetupProofStatement::VssShareLinkage(VssShareLinkageStatement {
            public_matrix_seed_hash,
            source_trustee_identity: primary_item.source_trustee_identity,
            source_trustee_roster_position: primary_item.source_trustee_roster_position,
            recipient_identity: primary_item.recipient_identity,
            recipient_roster_position: primary_item.recipient_roster_position,
            source_coefficient_commitment_root: primary_item.source_coefficient_commitment_root,
            source_recipient_share_commitment_root: primary_item
                .source_recipient_share_commitment_root,
            source_rns_limb_index: primary_item.source_rns_limb_index,
            coefficient_commitment_roots: primary_item.coefficient_commitment_roots,
            coefficient_commitments: primary_item.coefficient_commitments,
            recipient_share_commitment_root: primary_item.recipient_share_commitment_root,
            recipient_share_commitment: primary_item.recipient_share_commitment,
            additional_linkage_items,
            is_threshold_aggregate,
        }),
    };
    statement.validate_shape()?;

    Ok(statement)
}

pub(super) fn vss_share_linkage_witness_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyWitness> {
    Ok(TrusteeEvaluationKeyWitness::VssShareLinkage {
        coefficient_messages_by_shamir_index: read_i64_matrix2(
            request,
            "coefficientMessagesByShamirIndex",
        )?,
        recipient_share_messages_by_item: read_i64_matrix2(
            request,
            "recipientShareMessagesByItem",
        )?,
        carry_witnesses_by_item: read_i64_matrix2(request, "carryWitnessesByItem")?,
        committed_material: VssCommittedMaterialWitness {
            vss_committed_material_seeds_by_bound_message: read_string_array(
                request,
                "vssCommittedMaterialSeedsByBoundMessage",
            )?,
        },
    })
}

pub(in crate::bgv::setup::trustee_evaluation_key_proof) fn same_secret_bridge_statement_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let context_value = request
        .get("context")
        .ok_or_else(|| invalid_succinct_setup_proof("context must be present"))?;
    let ring_degree = usize::try_from(read_u64(request, "ringDegree")?)
        .map_err(|_| invalid_succinct_setup_proof("ringDegree does not fit usize"))?;
    let statement_value = request
        .get("sameSecretBridge")
        .ok_or_else(|| invalid_succinct_setup_proof("sameSecretBridge must be present"))?;
    let context = proof_context_from_value(
        context_value,
        SuccinctSetupProofFamilyShape::SameSecretBridge,
    )?;
    let same_secret_linkage = same_secret_linkage_from_statement_request(request)?;
    let bridge_fields = same_secret_bridge_fields_from_value(
        statement_value,
        &context,
        &same_secret_linkage.public_matrix_seed_hash,
        ring_degree,
    )?;

    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        proof: SetupProofStatement::SameSecretBridge {
            same_secret_linkage,
            same_secret_bridge: bridge_fields,
        },
    };
    statement.validate_shape()?;

    Ok(statement)
}

pub(super) fn same_secret_bridge_witness_from_request(
    request: &Value,
) -> CanonicalResult<TrusteeEvaluationKeyWitness> {
    let secret_coefficients = read_i64_array(request, "secretCoefficients")?;
    let negative_indicator_coefficients =
        super::negative_indicator_coefficients_from_ternary_secret(&secret_coefficients)?;
    Ok(TrusteeEvaluationKeyWitness::SameSecretBridge {
        secret_coefficients,
        linkage: SameSecretLinkageWitness {
            negative_indicator_coefficients,
            opening_randomness_by_limb: read_i64_matrix(request, "openingRandomnessByLimb")?,
        },
        committed_material: VssCommittedMaterialWitness {
            vss_committed_material_seeds_by_bound_message: read_string_array(
                request,
                "vssCommittedMaterialSeedsByBoundMessage",
            )?,
        },
    })
}

pub(super) fn vss_share_linkage_item_from_value(
    value: &Value,
    field_name: &str,
    ring_degree: usize,
    is_threshold_aggregate: bool,
) -> CanonicalResult<VssShareLinkageItem> {
    if !value.is_object() {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} must be an object"
        )));
    }
    // In threshold-aggregate mode the "coefficients" open recipient-share
    // committed material (the summands) and the "recipient share" opens
    // aggregate-threshold-share committed material (the sum). In ordinary
    // share-linkage mode they open coefficient and recipient-share material.
    let coefficient_commitment_role = if is_threshold_aggregate {
        "recipient-share"
    } else {
        "coefficient"
    };
    let recipient_commitment_role = if is_threshold_aggregate {
        "aggregate-threshold-share"
    } else {
        "recipient-share"
    };
    let source_rns_limb_index =
        usize::try_from(read_u64(value, "sourceRnsLimbIndex")?).map_err(|_| {
            invalid_succinct_setup_proof(format!(
                "{field_name}.sourceRnsLimbIndex does not fit usize"
            ))
        })?;
    let source_message_modulus =
        DATA_PRIMES
            .get(source_rns_limb_index)
            .copied()
            .ok_or_else(|| {
                invalid_succinct_setup_proof(format!(
                    "{field_name}.sourceRnsLimbIndex is outside the canonical modulus schedule"
                ))
            })?;
    let coefficient_commitment_roots = read_string_array(value, "coefficientCommitmentRoots")?;
    let coefficient_commitment_values = value
        .get("coefficientCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_succinct_setup_proof(format!(
                "{field_name}.coefficientCommitments must be an array"
            ))
        })?;
    if coefficient_commitment_values.len() != coefficient_commitment_roots.len() {
        return Err(invalid_succinct_setup_proof(format!(
            "{field_name} coefficient commitments and roots must be aligned"
        )));
    }
    let coefficient_commitments = coefficient_commitment_values
        .iter()
        .zip(coefficient_commitment_roots.iter())
        .enumerate()
        .map(
            |(coefficient_index, (commitment_value, expected_commitment_root))| {
                vss_share_linkage_commitment_from_value(
                    commitment_value,
                    VssPublicCommandCommitmentExpectation {
                        field_name: format!(
                            "{field_name}.coefficientCommitments.{coefficient_index}"
                        ),
                        root: expected_commitment_root,
                        role: coefficient_commitment_role,
                        rns_limb_index: source_rns_limb_index,
                        rns_prime: source_message_modulus,
                        ring_degree,
                    },
                )
            },
        )
        .collect::<CanonicalResult<Vec<_>>>()?;
    let recipient_share_commitment_root =
        read_string(value, "recipientShareCommitmentRoot")?.to_string();
    let recipient_share_commitment = vss_share_linkage_commitment_from_value(
        value.get("recipientShareCommitment").ok_or_else(|| {
            invalid_succinct_setup_proof(format!(
                "{field_name}.recipientShareCommitment must be present"
            ))
        })?,
        VssPublicCommandCommitmentExpectation {
            field_name: format!("{field_name}.recipientShareCommitment"),
            root: &recipient_share_commitment_root,
            role: recipient_commitment_role,
            rns_limb_index: source_rns_limb_index,
            rns_prime: source_message_modulus,
            ring_degree,
        },
    )?;

    Ok(VssShareLinkageItem {
        source_trustee_identity: read_string(value, "sourceTrusteeIdentity")?.to_string(),
        source_trustee_roster_position: read_u64(value, "sourceTrusteeRosterPosition")?,
        source_coefficient_commitment_root: read_string(value, "sourceCoefficientCommitmentRoot")?
            .to_string(),
        source_recipient_share_commitment_root: read_string(
            value,
            "sourceRecipientShareCommitmentRoot",
        )?
        .to_string(),
        recipient_identity: read_string(value, "recipientIdentity")?.to_string(),
        recipient_roster_position: read_u64(value, "recipientRosterPosition")?,
        source_rns_limb_index,
        coefficient_commitment_roots,
        coefficient_commitments,
        recipient_share_commitment_root,
        recipient_share_commitment,
    })
}

#[cfg(test)]
mod same_secret_bridge_witness_tests {
    use super::*;

    #[test]
    fn derives_negative_indicators_from_the_ternary_secret() {
        let mut request = serde_json::json!({
            "secretCoefficients": [-1, 0, 1],
            "openingRandomnessByLimb": [],
            "vssCommittedMaterialSeedsByBoundMessage": [],
        });
        let witness = same_secret_bridge_witness_from_request(&request)
            .expect("a ternary same-secret witness must parse");
        let TrusteeEvaluationKeyWitness::SameSecretBridge {
            secret_coefficients,
            linkage,
            ..
        } = witness
        else {
            panic!("the same-secret parser must return a same-secret witness");
        };
        assert_eq!(secret_coefficients, [-1, 0, 1]);
        assert_eq!(linkage.negative_indicator_coefficients, [1, 0, 0]);

        request["secretCoefficients"][1] = serde_json::json!(2);
        let Err(error) = same_secret_bridge_witness_from_request(&request) else {
            panic!("a non-ternary same-secret witness must reject");
        };
        assert!(
            error
                .to_string()
                .contains("secretCoefficients must contain only ternary coefficients"),
            "unexpected non-ternary secret error: {error}"
        );
    }
}
