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
            CanonicalErrorCode::ComponentMismatch,
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
            CanonicalErrorCode::ComponentMismatch,
            "target ciphertext pair does not match the accepted target ciphertext hash",
        ));
    }
    let target_ciphertext_binding_hash = derive_canonical_object_hash(&json!({
        "objectType": "TargetDecryptionCiphertextBinding",
        "aggregateCiphertextRoot": aggregate_ciphertext_root,
        "topCount": top_count,
        "targetLayoutHash": target_accepted.target_layout_hash,
        "targetIdRoot": target_id.root,
        "targetOrderRoot": target_order.root,
        "targetCiphertextHash": target_ciphertext_hash,
    }))?;

    Ok(TargetCiphertextPair {
        target_id: target_id.ciphertext,
        target_order: target_order.ciphertext,
        top_count,
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
                CanonicalErrorCode::ComponentMismatch,
                format!("{label} components must use the same data-basis level"),
            ));
        }
        components.push(component.residues_by_modulus);
    }

    Ok(ParsedTargetCiphertext {
        ciphertext: Ciphertext {
            components,
            level,
            // Target ciphertexts are produced pre-normalized to plaintext-scaling 1; recombination's mod-p step assumes this, so any other accumulated scaling would mis-decrypt.
            decrypt_scaling: 1,
        },
        root: ciphertext_root(&bytes),
    })
}

pub(crate) fn direct_target_ciphertext_hash(
    aggregate_ciphertext_root: &str,
    top_count: usize,
    target_layout_hash: &str,
    target_id_root: &str,
    target_order_root: &str,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "EncryptedSparseTargetCiphertext",
        "aggregateCiphertextRoot": aggregate_ciphertext_root,
        "topCount": top_count,
        "tiePolicy": TIE_POLICY,
        "targetLayoutHash": target_layout_hash,
        "targetIdRoot": target_id_root,
        "targetOrderRoot": target_order_root,
        "openedIntermediates": [],
    }))
}
