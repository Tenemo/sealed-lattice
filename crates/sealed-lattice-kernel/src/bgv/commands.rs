use serde_json::{Value, json};

use crate::{
    bgv::{
        parameters::{bgv_parameters_hash, bgv_parameters_value},
        setup::describe_collective_bgv_setup_parameters,
    },
    encoding::CanonicalResult,
};

pub(crate) fn describe_bgv_rns_parameters() -> CanonicalResult<Value> {
    Ok(json!({
        "parameters": bgv_parameters_value(),
        "bgvParametersHash": bgv_parameters_hash()?,
    }))
}

pub(crate) fn describe_collective_bgv_setup_parameters_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    match request.get("participantCount") {
        Some(value) => {
            let participant_count = value.as_u64().ok_or_else(|| {
                crate::encoding::CanonicalError::new(
                    crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
                    "participantCount must be an unsigned integer",
                )
            })?;
            crate::bgv::setup::describe_collective_bgv_setup_parameters_for_participant_count(
                participant_count,
            )
        }
        None => describe_collective_bgv_setup_parameters(),
    }
}

#[cfg(test)]
mod tests {
    use crate::bgv::{
        base_conversion::convert_plaintext_lifted_basis,
        encoding::encode_batch_plaintext_slots,
        parameters::BgvBasisKind,
        serialization::{BgvObjectKind, ciphertext_root, plaintext_root, serialize_bgv_object},
    };

    #[test]
    fn canonical_bgv_serialization_produces_stable_roots() {
        let encoded =
            encode_batch_plaintext_slots(&[0, 1, 65_536, 17, 99], 0).expect("encoded plaintext");
        let encoded_bytes = serialize_bgv_object(
            BgvObjectKind::Plaintext,
            std::slice::from_ref(&encoded.polynomial),
        )
        .expect("encoded plaintext canonical bytes");

        let left = encode_batch_plaintext_slots(&[1, 2, 3], 0).expect("left component");
        let right = encode_batch_plaintext_slots(&[4, 5, 6], 0).expect("right component");
        let ciphertext_bytes = serialize_bgv_object(
            BgvObjectKind::Ciphertext,
            &[left.polynomial, right.polynomial],
        )
        .expect("canonical ciphertext bytes");
        let encoded_ciphertext_root = ciphertext_root(&ciphertext_bytes);

        let source = encode_batch_plaintext_slots(&[7, 8, 9, 65_536], 0).expect("source plaintext");
        let converted =
            convert_plaintext_lifted_basis(&source.polynomial, BgvBasisKind::Extended, 1)
                .expect("base conversion");
        let source_bytes = serialize_bgv_object(
            BgvObjectKind::Plaintext,
            std::slice::from_ref(&source.polynomial),
        )
        .expect("source canonical bytes");
        let converted_bytes =
            serialize_bgv_object(BgvObjectKind::Plaintext, std::slice::from_ref(&converted))
                .expect("converted canonical bytes");
        let source_plaintext_root = plaintext_root(&source_bytes);
        let converted_plaintext_root = plaintext_root(&converted_bytes);
        assert_eq!(
            vec![
                plaintext_root(&encoded_bytes),
                encoded_ciphertext_root,
                source_plaintext_root.clone(),
                converted_plaintext_root.clone(),
            ],
            vec![
                "83babe666cc9e134ee31f1b3e64edf063302ff16b5c599292ba71d2d7270e8fc91067456eb09ffb69e63ff4064321099cdc09adbdaed57ac75102a7bcaa7c18d",
                "87b57a9fbed546496f5bef0adbb919b560249c84fe33c2ace3e71aa380faed69a9b14904f16be2216cb334a86990bcdf6674711fc5c52996d0cba85596123f27",
                "07ae82a666292ddd08bea917e2a05374938ef8b2d2b4c0410f5d534f42d4516bf9f200bb9b20f62d5b77bac7512a7f271f26312289d2ca402ca55533b15a241e",
                "0679d66690be7acd670b06bbf57b13c3cc342add3f147f2450ac8804f92623327b63e72ee3e993f8cb9a17950d3a9bc3cb655c740fc67b8c4d46efec3888d66f",
            ]
        );
        assert_eq!(converted.residues_by_modulus.len(), 2);
        assert_ne!(source_plaintext_root, converted_plaintext_root);
    }
}
