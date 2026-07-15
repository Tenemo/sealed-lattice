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
    match request.get("participantCount").and_then(Value::as_u64) {
        Some(participant_count) => {
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
                "0458603681ec68148da1b1e60edc083d253134d67c524db90255131ea5a79557f0aadc44a3bcbe59ee04fca388be4f08b2e532dc69dbc7dd52bc28fcdf123b65",
                "bb3962ea8e686cf9d5b4d5e5682709494faea0b2ddd76d71e2c48d52ca9157a1184aa93fa97fd89b5f130b10ffde70444c75b818c1a651bd080f5c73f6fa11fd",
                "2a25c79eba3e7ee884d925e57712792d1999125a62f36d854dae310dc5bf8a29a1f5d918af401b5bbb790333faeb176e8574d5c537efd34abb75e741f0348611",
                "56e08e7becd3fa35a12a2fbd10469fb49ff066953450892b20a4b02625324d7f38034ec0a9a0eedd5a764bd146bca19ab9b505669b60812c34446562ab03d35d",
            ]
        );
        assert_eq!(converted.moduli.len(), 2);
        assert_ne!(source_plaintext_root, converted_plaintext_root);
    }
}
