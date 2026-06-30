use super::*;

pub(super) fn direct_ballot_relation_statement_hash(
    setup_package: &Value,
    evaluator_key: &DevelopmentBgvKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<[u8; 64]> {
    let public_key_hash = direct_ballot_public_key_hash(evaluator_key)?;
    let statement_json = canonical_json(&json!({
        "objectType": "DirectEncryptedBallotValidityRelationStatement",
        "objectVersion": 4,
        "setupPackageHash": setup_package_hash(setup_package)?,
        "bgvParametersHash": bgv_parameters_hash()?,
        "publicKeyHash": to_hex(&public_key_hash),
        "ciphertextRoot": ballot.ciphertext_root.as_str(),
        "ciphertextCanonicalByteLength": ballot.ciphertext_canonical_byte_length,
        "voterIdentity": ballot.input.voter_identity.as_str(),
        "actionContextHash": ballot.input.action_context_hash.as_str(),
        "optionCount": DIRECT_BALLOT_OPTION_COUNT,
        "scoreRange": format!("1..={DIRECT_BALLOT_MAXIMUM_SCORE}"),
        "relation": "score and one-hot linear constraints, one-hot Booleanity, randomizer and error support, plus c0=b*u+p*encode(score)+p*e0 and c1=a*u+p*e1 for every BGV data prime"
    }))?;

    Ok(hash512(
        "sealed-lattice/direct-encrypted-ballot/relation-statement-v4",
        &[statement_json.as_bytes()],
    ))
}

pub(super) fn direct_ballot_public_key_hash(
    evaluator_key: &DevelopmentBgvKey,
) -> CanonicalResult<[u8; 64]> {
    let (public_component_zero, public_component_one) = evaluator_key.public_key_components();
    if public_component_zero.len() != DATA_PRIMES.len()
        || public_component_one.len() != DATA_PRIMES.len()
    {
        return Err(invalid_direct_ballot_relation_proof(
            "direct ballot relation proof requires a full BGV public key",
        ));
    }
    let mut encoded = Vec::with_capacity(DATA_PRIMES.len() * 2 * POLYNOMIAL_DEGREE * 8);
    append_u64(&mut encoded, DATA_PRIMES.len() as u64);
    for modulus in DATA_PRIMES {
        append_u64(&mut encoded, modulus);
    }
    encode_public_key_component(&mut encoded, public_component_zero, "component zero")?;
    encode_public_key_component(&mut encoded, public_component_one, "component one")?;

    Ok(hash512(
        "sealed-lattice/direct-encrypted-ballot/public-key-v1",
        &[&encoded],
    ))
}

pub(super) fn encode_public_key_component(
    output: &mut Vec<u8>,
    component: &[Vec<u64>],
    label: &str,
) -> CanonicalResult<()> {
    for (limb_index, (limb, modulus)) in component.iter().zip(DATA_PRIMES.iter()).enumerate() {
        if limb.len() != POLYNOMIAL_DEGREE {
            return Err(invalid_direct_ballot_relation_proof(format!(
                "direct ballot relation proof public key {label} limb {limb_index} has the wrong degree"
            )));
        }
        for coefficient in limb {
            if *coefficient >= *modulus {
                return Err(invalid_direct_ballot_relation_proof(format!(
                    "direct ballot relation proof public key {label} limb {limb_index} has a non-canonical coefficient"
                )));
            }
            append_u64(output, *coefficient);
        }
    }

    Ok(())
}
