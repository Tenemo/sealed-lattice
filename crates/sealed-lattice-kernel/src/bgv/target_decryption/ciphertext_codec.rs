use super::*;

pub(super) fn read_target_ciphertext_pair(
    ciphertexts: &Value,
    binding: &Value,
    target_accepted: &TargetAcceptedBinding,
) -> CanonicalResult<TargetCiphertextPair> {
    let target_id = parse_target_ciphertext(
        string_at_path(ciphertexts, &["targetIdCanonicalBytesHex"])?,
        "target id ciphertext",
    )?;
    let target_order = parse_target_ciphertext(
        string_at_path(ciphertexts, &["targetOrderCanonicalBytesHex"])?,
        "target order ciphertext",
    )?;
    if target_id.ciphertext.level != target_order.ciphertext.level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target id and target order ciphertexts must use the same BGV level",
        ));
    }
    compare_hash_field(
        binding,
        "targetLayoutHash",
        &target_accepted.target_layout_hash,
        "target ciphertext layout hash",
    )?;
    let aggregate_ciphertext_root = hash_at_path(binding, &["aggregateCiphertextRoot"])?;
    let top_count = usize_field(binding, "topCount")?;
    if top_count == 0 || top_count > MAXIMUM_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target ciphertext binding topCount is outside the supported option count",
        ));
    }
    let target_ciphertext_hash = direct_target_ciphertext_hash(
        aggregate_ciphertext_root,
        top_count,
        &target_accepted.target_layout_hash,
        &target_id.root,
        &target_order.root,
    )?;
    if target_ciphertext_hash != target_accepted.target_ciphertext_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target ciphertext pair does not match the accepted target ciphertext hash",
        ));
    }
    let target_ciphertext_binding_hash = derive_protocol_hash(
        "TargetDecryptionCiphertextBindingHash",
        &json!({
            "objectType": "TargetDecryptionCiphertextBinding",
            "objectVersion": 1,
            "aggregateCiphertextRoot": aggregate_ciphertext_root,
            "topCount": top_count,
            "targetLayoutHash": target_accepted.target_layout_hash,
            "targetIdRoot": target_id.root,
            "targetOrderRoot": target_order.root,
            "targetCiphertextHash": target_ciphertext_hash,
        }),
    )?;

    Ok(TargetCiphertextPair {
        target_id: target_id.ciphertext,
        target_order: target_order.ciphertext,
        target_id_root: target_id.root,
        target_order_root: target_order.root,
        target_ciphertext_hash,
        target_ciphertext_binding_hash,
    })
}

pub(super) struct ParsedTargetCiphertext {
    ciphertext: Ciphertext,
    root: String,
}

pub(super) fn parse_target_ciphertext(
    canonical_bytes_hex_value: &str,
    label: &str,
) -> CanonicalResult<ParsedTargetCiphertext> {
    let bytes = decode_hex(canonical_bytes_hex_value)?;
    let object = parse_bgv_object(&bytes)?;
    if object.object_kind != BgvObjectKind::Ciphertext || object.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} must be a two-component BGV ciphertext"),
        ));
    }
    let level = object.components[0].level;
    let basis_id = BgvBasisKind::Data.basis_id();
    let mut components = Vec::with_capacity(2);
    for component in object.components {
        if component.level != level || component.basis_id != basis_id {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("{label} components must use the same data-basis level"),
            ));
        }
        components.push(component.residues_by_modulus);
    }

    Ok(ParsedTargetCiphertext {
        ciphertext: Ciphertext {
            components,
            level,
            decrypt_scaling: 1,
        },
        root: ciphertext_root(&bytes),
    })
}

pub(super) fn direct_target_ciphertext_hash(
    aggregate_ciphertext_root: &str,
    top_count: usize,
    target_layout_hash: &str,
    target_id_root: &str,
    target_order_root: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "EncryptedSparseTargetProjectionHash",
        &json!({
            "objectType": "EncryptedSparseTargetCiphertext",
            "objectVersion": 1,
            "aggregateCiphertextRoot": aggregate_ciphertext_root,
            "topCount": top_count,
            "tiePolicy": TIE_POLICY,
            "targetLayoutHash": target_layout_hash,
            "targetIdRoot": target_id_root,
            "targetOrderRoot": target_order_root,
            "openedIntermediates": [],
        }),
    )
}

pub(super) fn coefficient_vector_bytes(coefficients: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(coefficients.len() * 8);
    for coefficient in coefficients {
        bytes.extend(coefficient.to_le_bytes());
    }
    bytes
}

pub(super) fn coefficient_vector_le_hex(coefficients: &[u64]) -> String {
    encode_hex(&coefficient_vector_bytes(coefficients))
}

pub(super) fn coefficient_vector_from_le_hex(value: &str) -> CanonicalResult<Vec<u64>> {
    let bytes = decode_hex(value)?;
    if bytes.len() != POLYNOMIAL_DEGREE * 8 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target partial-decryption coefficient vector byte length does not match the selected BGV profile",
        ));
    }
    Ok(bytes
        .chunks_exact(8)
        .map(|chunk| {
            let mut coefficient_bytes = [0_u8; 8];
            coefficient_bytes.copy_from_slice(chunk);
            u64::from_le_bytes(coefficient_bytes)
        })
        .collect())
}
