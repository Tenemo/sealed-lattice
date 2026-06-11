use super::*;

pub(super) fn evaluation_key_share_lnp_statement_value(
    input: &EvaluationKeyShareLnpProofVerificationInput<'_>,
    component_b_by_digit: &[Vec<Vec<u64>>],
) -> CanonicalResult<Value> {
    let level = value_usize(input.proof_record, "level")?;
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    let key_switch_domain = string_field(input.proof_record, "keySwitchDomain")?;
    let key_switch_seed_hex = string_field(input.proof_record, "keySwitchSeedHex")?;
    let constant_commitment_roots = input
        .constant_commitments
        .iter()
        .enumerate()
        .map(|(rns_limb_index, commitment)| {
            Ok(json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": DATA_PRIMES[rns_limb_index],
                "shamirCoefficientIndex": 0,
                "commitmentRoot": setup_commitment_root(commitment)?,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let source_relation = match input.proof_family {
        EvaluationKeyShareProofFamily::Relinearization
            if relinearization_record_uses_same_secret_source(input.proof_record) =>
        {
            "round-one source response is the same response vector as the committed trustee secret"
        }
        EvaluationKeyShareProofFamily::Relinearization => {
            "round-two source response is bound as a hidden contribution to the aggregate squared secret; verifier checks source-square binding roots and aggregate roots"
        }
        EvaluationKeyShareProofFamily::Galois => {
            "source response is the public Galois automorphism applied to the same-secret response"
        }
    };

    let mut statement = json!({
        "objectType": input.proof_family.relation_statement_object_type(),
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "setupProofBinding": input.setup_proof_binding,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "proofProfileId": input.proof_family.proof_profile_id(),
        "proofFamily": input.proof_family.proof_family(),
        "proofVerificationStatus": input.proof_family.proof_verification_status(),
        "proofModelStatus": input.proof_family.proof_model_status(),
        "recordStatement": proof_record_statement_projection(input.proof_record),
        "sameSecretStatementRoot": input.proof_record["sameSecretStatementRoot"],
        "trusteeSecretCommitmentRoot": input.proof_record["trusteeSecretCommitmentRoot"],
        "sameSecretProofRoot": input.proof_record["sameSecretProofRoot"],
        "sameSecretProofFamilyBindingRoot": input.proof_record["sameSecretProofFamilyBindingRoot"],
        "constantCoefficientCommitmentRoots": constant_commitment_roots,
        "keySwitchDomain": key_switch_domain,
        "keySwitchSeedHex": key_switch_seed_hex,
        "level": level,
        "ringDegree": ring_degree,
        "digitCount": component_b_by_digit.len(),
        "rnsLimbCount": component_b_by_digit.first().map(Vec::len).unwrap_or_default(),
        "relation": "for every digit j and limb l, b_j,l + a_j,l*s - p*e_j - source_j,l - q_l*v_j,l = 0 over lifted integers",
        "sourceRelation": source_relation,
        "claimClosure": match input.proof_family {
            EvaluationKeyShareProofFamily::Relinearization => "linear key-switch relation, same-secret binding, round-one same-secret source response, public component material, tbox byte layout, response bounds, relinearization source record binding, verifier-side round-two source-square aggregate roots, and accepted setup proof soundness, zero-knowledge, and QROM accounting are verified",
            EvaluationKeyShareProofFamily::Galois => "linear key-switch relation, same-secret binding, Galois automorphism source response, public component material, tbox byte layout, response bounds, and accepted setup proof soundness, zero-knowledge, and QROM accounting are verified",
        },
    });
    statement[input.proof_family.tbox_parameter_profile_hash_field()] =
        json!(input.proof_family.tbox_parameter_profile_hash()?);

    Ok(statement)
}

pub(super) fn relinearization_record_uses_same_secret_source(proof_record: &Value) -> bool {
    proof_record.get("objectType").and_then(Value::as_str)
        == Some(RELINEARIZATION_KEY_SHARE_ROUND_ONE_OBJECT_TYPE)
}

fn proof_record_statement_projection(record: &Value) -> Value {
    let mut projection = record.clone();
    let Some(object) = projection.as_object_mut() else {
        return projection;
    };
    for field_name in [
        "roundOneRecordRoot",
        "roundTwoRecordRoot",
        "galoisKeyShareProofRoot",
        "roundOneProofRoot",
        "roundTwoProofRoot",
        "sourceSquareBindingRoot",
        "roundOneSourceSquareBindingRoot",
        "roundOneSourceSquareAggregateRoot",
        "proofBytesEncoding",
        "proofMaterialRoot",
        "proofChunkSizeBytes",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
        "statementHash",
        "relationCommitmentHash",
        "tboxCommitmentPrefixHash",
        "z34SeedMaterialHash",
        "z34ChallengeSeedHash",
        "z34ChallengeTailHash",
        "z34ChallengeRowDomainHash",
        "z34ChallengeZ3RowSetHash",
        "z34ChallengeZ4RowSetHash",
        "tboxLowerProtocolChallengeHash",
        "z34Z3CheckWindowHash",
        "z34Z4CheckWindowHash",
        "z34Z3L2SquaredDecimal",
        "z34Z4InfinityNormDecimal",
        "challenge",
        "proofSizeBytes",
        "proofBytesHash",
        "proofBytesHex",
    ] {
        object.remove(field_name);
    }

    projection
}

pub(super) fn evaluation_key_share_lnp_statement_hash(
    proof_family: EvaluationKeyShareProofFamily,
    statement_value: &Value,
) -> CanonicalResult<[u8; 64]> {
    let statement_json = canonical_json(statement_value)?;
    Ok(hash512(
        match proof_family {
            EvaluationKeyShareProofFamily::Relinearization => {
                "sealed-lattice/setup/relinearization-key-share/lnp-relation-statement-v1"
            }
            EvaluationKeyShareProofFamily::Galois => {
                "sealed-lattice/setup/galois-key-share/lnp-relation-statement-v1"
            }
        },
        &[statement_json.as_bytes()],
    ))
}
