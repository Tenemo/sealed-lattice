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
        encoding::encode_batch_plaintext_lanes,
        parameters::BgvBasisKind,
        serialization::{BgvObjectKind, ciphertext_root, plaintext_root, serialize_bgv_object},
    };

    #[test]
    fn canonical_bgv_serialization_produces_stable_roots() {
        let encoded =
            encode_batch_plaintext_lanes(&[0, 1, 256, 17, 99], 0).expect("encoded plaintext");
        let encoded_bytes = serialize_bgv_object(
            BgvObjectKind::Plaintext,
            std::slice::from_ref(&encoded.polynomial),
        )
        .expect("encoded plaintext canonical bytes");

        let left = encode_batch_plaintext_lanes(&[1, 2, 3], 0).expect("left component");
        let right = encode_batch_plaintext_lanes(&[4, 5, 6], 0).expect("right component");
        let ciphertext_bytes = serialize_bgv_object(
            BgvObjectKind::Ciphertext,
            &[left.polynomial, right.polynomial],
        )
        .expect("canonical ciphertext bytes");
        let encoded_ciphertext_root = ciphertext_root(&ciphertext_bytes);

        let source = encode_batch_plaintext_lanes(&[7, 8, 9, 256], 0).expect("source plaintext");
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
                "f8a4bf5292d85ac5c6394de9dbce3998df15e626c8304e96051fc1d12de6b1ca595a96bbdcd59aecc59c77eeafab74939a7740957d393c81207a93d1b5a259a8",
                "0e01e54f578973532d67d2650f2953626ac96cc1c6a7171946298dd891c211e46d4c214ec0aa79176ccfe5dd9896e5ddbfad51acab77b43594842dab887ff3a7",
                "ab02ce34aceaddc4bf4e106456f10bc98164b50d245d84126d8504e2db2ca2955b03621343624323311aba2066cd940d2d3c8a9efcefc665899cf88898791ca6",
                "8c82cfbc84b373ad537e40b59e19686d2afeafb3e5984634af4c32da66495774d1f7c6ea196446b87d3464dc939c3f3ba768c1b3a5fbbb16f48a08406a4bed37",
            ]
        );
        assert_eq!(converted.residues_by_modulus.len(), 2);
        assert_ne!(source_plaintext_root, converted_plaintext_root);
    }
}
