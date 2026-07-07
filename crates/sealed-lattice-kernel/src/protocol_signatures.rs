#[cfg(test)]
use fips204::traits::{KeyGen, Signer};
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};
use serde_json::{Value, json};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, derive_canonical_object_hash},
    transcript_core::decode_hex,
};

const ML_DSA_65_ALGORITHM: &str = "ML-DSA-65";
const PURE_ML_DSA_MODE: &str = "PureMLDSA";
const ML_DSA_CONTEXT_BYTE_LIMIT: usize = 255;
const PROTOCOL_SIGNATURE_MESSAGE_DOMAIN: &str = "sealed-lattice/protocol-signature-v1";
const SUPPORTED_ML_DSA_CONTEXT_STRING: &str = "sealed-lattice:v1";
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug)]
pub(crate) struct ProtocolSignatureExpectation<'a> {
    pub object_type: &'a str,
    pub signer_role: &'a str,
    pub signer_identity: &'a str,
    pub ceremony_id: &'a str,
    pub public_key_hash: &'a str,
    pub manifest_hash: Option<&'a str>,
    pub object_root: Option<&'a str>,
    pub chunk_merkle_root: Option<&'a str>,
    pub board_head_hash: Option<&'a str>,
    pub context_hash: &'a str,
    pub recovery_epoch: u64,
    pub device_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProtocolSignatureFailure {
    pub reason_code: &'static str,
    pub message: String,
    pub object_hash: Option<String>,
}

impl ProtocolSignatureFailure {
    fn new(
        reason_code: &'static str,
        message: impl Into<String>,
        signature: Option<&Value>,
    ) -> Self {
        Self {
            reason_code,
            message: message.into(),
            object_hash: signature
                .and_then(|signature| signature.get("signatureHash"))
                .and_then(Value::as_str)
                .map(str::to_string),
        }
    }
}

pub(crate) fn verify_protocol_signature_envelope(
    signature: &Value,
    expectation: &ProtocolSignatureExpectation<'_>,
) -> CanonicalResult<Result<String, ProtocolSignatureFailure>> {
    if !signature.is_object() {
        return Ok(Err(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Signature envelope must be a JSON object.",
            Some(signature),
        )));
    }

    if let Some(failure) = validate_profile(signature) {
        return Ok(Err(failure));
    }
    if let Some(failure) = validate_signature_material(signature)? {
        return Ok(Err(failure));
    }
    if let Some(failure) = validate_signed_root_shape(signature) {
        return Ok(Err(failure));
    }
    if let Some(failure) = validate_expectation(signature, expectation) {
        return Ok(Err(failure));
    }
    if let Some(failure) = validate_signature_hash(signature)? {
        return Ok(Err(failure));
    }
    if let Some(failure) = verify_ml_dsa_signature(signature)? {
        return Ok(Err(failure));
    }

    Ok(Ok(signature
        .get("signatureHash")
        .and_then(Value::as_str)
        .expect("signature hash was validated")
        .to_string()))
}

fn validate_profile(signature: &Value) -> Option<ProtocolSignatureFailure> {
    let Some(profile) = signature.get("profile").and_then(Value::as_object) else {
        return Some(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Signature envelope must include a profile object.",
            Some(signature),
        ));
    };
    let Some(context_string) = profile.get("contextString").and_then(Value::as_str) else {
        return Some(ProtocolSignatureFailure::new(
            "InvalidMlDsaContext",
            "Signature profile must bind an ML-DSA context string.",
            Some(signature),
        ));
    };
    if profile.get("algorithm").and_then(Value::as_str) != Some(ML_DSA_65_ALGORITHM) {
        return Some(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Signature profile must use ML-DSA-65.",
            Some(signature),
        ));
    }
    if profile.get("mode").and_then(Value::as_str) != Some(PURE_ML_DSA_MODE) {
        return Some(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Only PureMLDSA signatures are supported by this verifier.",
            Some(signature),
        ));
    }
    let actual_context_byte_length = context_string.len();
    if actual_context_byte_length > ML_DSA_CONTEXT_BYTE_LIMIT {
        return Some(ProtocolSignatureFailure::new(
            "InvalidMlDsaContext",
            "ML-DSA context strings must be at most 255 bytes.",
            Some(signature),
        ));
    }
    if context_string != SUPPORTED_ML_DSA_CONTEXT_STRING {
        return Some(ProtocolSignatureFailure::new(
            "InvalidMlDsaContext",
            "ML-DSA context string does not match the supported protocol context.",
            Some(signature),
        ));
    }

    None
}

fn validate_signature_material(
    signature: &Value,
) -> CanonicalResult<Option<ProtocolSignatureFailure>> {
    let Some(public_key_bytes_hex) = signature.get("publicKeyBytesHex").and_then(Value::as_str)
    else {
        return Ok(Some(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Signature envelope must bind publicKeyBytesHex.",
            Some(signature),
        )));
    };
    let Some(public_key_hash) = signature.get("publicKeyHash").and_then(Value::as_str) else {
        return Ok(Some(ProtocolSignatureFailure::new(
            "WrongPublicKey",
            "Signature envelope must bind publicKeyHash.",
            Some(signature),
        )));
    };
    let Some(signature_bytes_hex) = signature.get("signatureBytesHex").and_then(Value::as_str)
    else {
        return Ok(Some(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Signature envelope must bind signatureBytesHex.",
            Some(signature),
        )));
    };

    if decode_hex_field(public_key_bytes_hex, ml_dsa_65::PK_LEN).is_err()
        || decode_hex_field(signature_bytes_hex, ml_dsa_65::SIG_LEN).is_err()
    {
        return Ok(Some(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Signature envelope contains malformed ML-DSA key or signature bytes.",
            Some(signature),
        )));
    }
    if !is_protocol_hash_string(public_key_hash) {
        return Ok(Some(ProtocolSignatureFailure::new(
            "WrongPublicKey",
            "Signature public key hash must be a canonical protocol hash.",
            Some(signature),
        )));
    }

    let expected_public_key_hash = derive_ml_dsa_public_key_hash(public_key_bytes_hex)?;
    if public_key_hash != expected_public_key_hash {
        return Ok(Some(ProtocolSignatureFailure::new(
            "WrongPublicKey",
            "Signature public key hash does not match the ML-DSA public key bytes.",
            Some(signature),
        )));
    }

    Ok(None)
}

fn validate_signed_root_shape(signature: &Value) -> Option<ProtocolSignatureFailure> {
    let Some(signed_root) = signature.get("signedRoot").and_then(Value::as_object) else {
        return Some(ProtocolSignatureFailure::new(
            "InvalidSignedRoot",
            "Signature envelope must include a signedRoot object.",
            Some(signature),
        ));
    };

    for field_name in [
        "objectType",
        "ceremonyId",
        "manifestHash",
        "boardHeadHash",
        "objectRoot",
        "chunkMerkleRoot",
        "signerRole",
        "signerIdentity",
        "recoveryEpoch",
        "deviceEpoch",
        "contextHash",
    ] {
        if !signed_root.contains_key(field_name) {
            return Some(ProtocolSignatureFailure::new(
                "InvalidSignedRoot",
                format!("Signed roots must bind {field_name}."),
                Some(signature),
            ));
        }
    }

    let object_root_present = signed_root
        .get("objectRoot")
        .and_then(Value::as_str)
        .is_some();
    let chunk_root_present = signed_root
        .get("chunkMerkleRoot")
        .and_then(Value::as_str)
        .is_some();
    if !object_root_present && !chunk_root_present {
        return Some(ProtocolSignatureFailure::new(
            "InvalidSignedRoot",
            "Signed roots must bind an object root or chunk Merkle root.",
            Some(signature),
        ));
    }
    if object_root_present && chunk_root_present {
        return Some(ProtocolSignatureFailure::new(
            "InvalidSignedRoot",
            "Signed roots must bind exactly one object root or chunk Merkle root.",
            Some(signature),
        ));
    }

    for field_name in [
        "objectRoot",
        "chunkMerkleRoot",
        "manifestHash",
        "boardHeadHash",
    ] {
        if !is_protocol_hash_or_null(signed_root.get(field_name)) {
            return Some(ProtocolSignatureFailure::new(
                "InvalidSignedRoot",
                "Signed-root hash bindings must be canonical hash strings or null.",
                Some(signature),
            ));
        }
    }
    if !signed_root
        .get("contextHash")
        .and_then(Value::as_str)
        .is_some_and(is_protocol_hash_string)
    {
        return Some(ProtocolSignatureFailure::new(
            "InvalidSignedRoot",
            "Signed-root context hash must be a canonical hash string.",
            Some(signature),
        ));
    }

    for field_name in ["recoveryEpoch", "deviceEpoch"] {
        if signed_root
            .get(field_name)
            .and_then(Value::as_u64)
            .is_none_or(|value| value > MAX_SAFE_JSON_INTEGER)
        {
            return Some(ProtocolSignatureFailure::new(
                "InvalidSignedRoot",
                "Signed root byte length and epochs must be safe non-negative integers.",
                Some(signature),
            ));
        }
    }
    for field_name in ["objectType", "ceremonyId", "signerRole", "signerIdentity"] {
        if signed_root
            .get(field_name)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Some(ProtocolSignatureFailure::new(
                "InvalidSignedRoot",
                "Signed roots must bind non-empty object, ceremony, role, and signer identity strings.",
                Some(signature),
            ));
        }
    }

    None
}

fn validate_expectation(
    signature: &Value,
    expectation: &ProtocolSignatureExpectation<'_>,
) -> Option<ProtocolSignatureFailure> {
    let signed_root = signature
        .get("signedRoot")
        .expect("signed root was checked before expectation validation");

    if signed_root.get("objectType").and_then(Value::as_str) != Some(expectation.object_type) {
        return Some(ProtocolSignatureFailure::new(
            "WrongObjectType",
            "Signature root object type does not match the expected object.",
            Some(signature),
        ));
    }
    if signed_root.get("signerRole").and_then(Value::as_str) != Some(expectation.signer_role) {
        return Some(ProtocolSignatureFailure::new(
            "WrongSignerRole",
            "Signature root signer role does not match the expected role.",
            Some(signature),
        ));
    }
    if signed_root.get("signerIdentity").and_then(Value::as_str)
        != Some(expectation.signer_identity)
    {
        return Some(ProtocolSignatureFailure::new(
            "InvalidSignedRoot",
            "Signature root signer identity does not match the expected identity.",
            Some(signature),
        ));
    }
    if signed_root.get("ceremonyId").and_then(Value::as_str) != Some(expectation.ceremony_id) {
        return Some(ProtocolSignatureFailure::new(
            "WrongCeremony",
            "Signature root ceremony does not match the expected ceremony.",
            Some(signature),
        ));
    }
    if signature.get("publicKeyHash").and_then(Value::as_str) != Some(expectation.public_key_hash) {
        return Some(ProtocolSignatureFailure::new(
            "WrongPublicKey",
            "Signature public key hash does not match the expected key.",
            Some(signature),
        ));
    }

    for (field_name, expected_hash) in [
        ("manifestHash", expectation.manifest_hash),
        ("objectRoot", expectation.object_root),
        ("chunkMerkleRoot", expectation.chunk_merkle_root),
        ("boardHeadHash", expectation.board_head_hash),
    ] {
        if !hash_or_null_equals(signed_root.get(field_name), expected_hash) {
            return Some(ProtocolSignatureFailure::new(
                "InvalidSignedRoot",
                format!("Signature root {field_name} does not match the expected binding."),
                Some(signature),
            ));
        }
    }
    if signed_root.get("contextHash").and_then(Value::as_str) != Some(expectation.context_hash) {
        return Some(ProtocolSignatureFailure::new(
            "InvalidSignedRoot",
            "Signature root context hash does not match the expected context.",
            Some(signature),
        ));
    }
    if signed_root.get("recoveryEpoch").and_then(Value::as_u64) != Some(expectation.recovery_epoch)
        || signed_root.get("deviceEpoch").and_then(Value::as_u64) != Some(expectation.device_epoch)
    {
        return Some(ProtocolSignatureFailure::new(
            "InvalidSignedRoot",
            "Signature root epochs do not match the expected object.",
            Some(signature),
        ));
    }

    None
}

fn validate_signature_hash(signature: &Value) -> CanonicalResult<Option<ProtocolSignatureFailure>> {
    let Some(signature_hash) = signature.get("signatureHash").and_then(Value::as_str) else {
        return Ok(Some(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Signature envelope must bind signatureHash.",
            Some(signature),
        )));
    };
    if !is_protocol_hash_string(signature_hash) {
        return Ok(Some(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Signature hash must be a canonical protocol hash.",
            Some(signature),
        )));
    }

    let expected_signature_hash = derive_protocol_signature_hash(signature)?;
    if signature_hash != expected_signature_hash {
        return Ok(Some(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Signature hash does not verify for the canonical signed root.",
            Some(signature),
        )));
    }

    Ok(None)
}

fn verify_ml_dsa_signature(signature: &Value) -> CanonicalResult<Option<ProtocolSignatureFailure>> {
    let public_key_bytes_hex = signature
        .get("publicKeyBytesHex")
        .and_then(Value::as_str)
        .expect("public key bytes were validated");
    let signature_bytes_hex = signature
        .get("signatureBytesHex")
        .and_then(Value::as_str)
        .expect("signature bytes were validated");
    let profile = signature.get("profile").expect("profile was validated");
    let context_string = profile
        .get("contextString")
        .and_then(Value::as_str)
        .expect("context string was validated");

    let public_key_bytes = decode_hex_field(public_key_bytes_hex, ml_dsa_65::PK_LEN)
        .expect("public key byte length was validated");
    let signature_bytes = decode_hex_field(signature_bytes_hex, ml_dsa_65::SIG_LEN)
        .expect("signature byte length was validated");
    let public_key_array: [u8; ml_dsa_65::PK_LEN] = public_key_bytes
        .try_into()
        .expect("public key byte length was checked");
    let signature_array: [u8; ml_dsa_65::SIG_LEN] = signature_bytes
        .try_into()
        .expect("signature byte length was checked");
    let Ok(public_key) = ml_dsa_65::PublicKey::try_from_bytes(public_key_array) else {
        return Ok(Some(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "ML-DSA public key bytes are not accepted by the verifier.",
            Some(signature),
        )));
    };
    let message = canonical_protocol_signature_message(signature)?;
    if !public_key.verify(
        message.as_bytes(),
        &signature_array,
        context_string.as_bytes(),
    ) {
        return Ok(Some(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "ML-DSA signature does not verify for the canonical signed root.",
            Some(signature),
        )));
    }

    Ok(None)
}

fn canonical_protocol_signature_message(signature: &Value) -> CanonicalResult<String> {
    let profile = signature.get("profile").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "signature profile was not available for message encoding",
        )
    })?;
    let public_key_hash = signature.get("publicKeyHash").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "signature publicKeyHash was not available for message encoding",
        )
    })?;
    let signed_root = signature.get("signedRoot").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "signature signedRoot was not available for message encoding",
        )
    })?;

    canonical_json(&json!({
        "messageDomain": PROTOCOL_SIGNATURE_MESSAGE_DOMAIN,
        "profile": profile,
        "publicKeyHash": public_key_hash,
        "signedRoot": signed_root,
    }))
}

fn derive_ml_dsa_public_key_hash(public_key_bytes_hex: &str) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "MlDsaPublicKeyHash",
        "algorithm": ML_DSA_65_ALGORITHM,
        "publicKeyBytesHex": public_key_bytes_hex,
    }))
}

fn derive_protocol_signature_hash(signature: &Value) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
    "objectType": "ProtocolSignatureEnvelope",
    "profile": signature
        .get("profile")
        .expect("signature profile was validated"),
        "publicKeyBytesHex": signature
            .get("publicKeyBytesHex")
            .expect("public key bytes were validated"),
        "publicKeyHash": signature
            .get("publicKeyHash")
            .expect("public key hash was validated"),
        "signatureBytesHex": signature
            .get("signatureBytesHex")
            .expect("signature bytes were validated"),
        "signedRoot": signature
            .get("signedRoot")
            .expect("signed root was validated"),
    }))
}

fn decode_hex_field(value: &str, expected_byte_length: usize) -> Result<Vec<u8>, ()> {
    let bytes = decode_hex(value).map_err(|_| ())?;
    if bytes.len() != expected_byte_length {
        return Err(());
    }

    Ok(bytes)
}

fn is_protocol_hash_string(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_protocol_hash_or_null(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Null) => true,
        Some(Value::String(hash)) => is_protocol_hash_string(hash),
        _ => false,
    }
}

fn hash_or_null_equals(value: Option<&Value>, expected_hash: Option<&str>) -> bool {
    match (value, expected_hash) {
        (Some(Value::Null), None) => true,
        (Some(Value::String(actual_hash)), Some(expected_hash)) => actual_hash == expected_hash,
        _ => false,
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ProtocolSignatureFixture {
    pub public_key_hash: String,
    pub envelope: Value,
}

#[cfg(test)]
pub(crate) fn create_protocol_signature_fixture(
    seed_label: &str,
    signed_root: Value,
) -> CanonicalResult<ProtocolSignatureFixture> {
    let seed = key_fixture_seed(seed_label)?;
    let (public_key, private_key) = ml_dsa_65::KG::keygen_from_seed(&seed);
    let public_key_bytes_hex = crate::hashing::to_hex(&public_key.into_bytes());
    let public_key_hash = derive_ml_dsa_public_key_hash(&public_key_bytes_hex)?;
    let profile = create_ml_dsa_signature_profile_fixture()?;
    let message_input = json!({
        "profile": profile,
        "publicKeyHash": public_key_hash,
        "signedRoot": signed_root,
    });
    let message = canonical_protocol_signature_message(&message_input)?;
    let signature_seed = fixture_seed("ml-dsa-signature-fixture-seed", seed_label, &signed_root)?;
    let signature_bytes = private_key
        .try_sign_with_seed(
            &signature_seed,
            message.as_bytes(),
            SUPPORTED_ML_DSA_CONTEXT_STRING.as_bytes(),
        )
        .map_err(|error| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("ML-DSA fixture signing failed: {error}"),
            )
        })?;
    let mut envelope = json!({
        "profile": profile,
        "publicKeyBytesHex": public_key_bytes_hex,
        "publicKeyHash": public_key_hash,
        "signatureBytesHex": crate::hashing::to_hex(&signature_bytes),
        "signedRoot": signed_root,
    });
    let signature_hash = derive_protocol_signature_hash(&envelope)?;
    envelope["signatureHash"] = Value::String(signature_hash);

    Ok(ProtocolSignatureFixture {
        public_key_hash,
        envelope,
    })
}

#[cfg(test)]
pub(crate) fn create_ml_dsa_public_key_hash_fixture(seed_label: &str) -> CanonicalResult<String> {
    let seed = key_fixture_seed(seed_label)?;
    let (public_key, _) = ml_dsa_65::KG::keygen_from_seed(&seed);
    let public_key_bytes_hex = crate::hashing::to_hex(&public_key.into_bytes());

    derive_ml_dsa_public_key_hash(&public_key_bytes_hex)
}

#[cfg(test)]
fn create_ml_dsa_signature_profile_fixture() -> CanonicalResult<Value> {
    Ok(json!({
        "algorithm": ML_DSA_65_ALGORITHM,
        "mode": PURE_ML_DSA_MODE,
        "contextString": SUPPORTED_ML_DSA_CONTEXT_STRING,
    }))
}

#[cfg(test)]
fn fixture_seed(purpose: &str, seed_label: &str, signed_root: &Value) -> CanonicalResult<[u8; 32]> {
    let seed_hash = derive_canonical_object_hash(&json!({
        "objectType": "MlDsaSignatureFixtureSeed",
        "purpose": purpose,
        "seedLabel": seed_label,
        "signedRoot": signed_root,
    }))?;
    let seed_bytes = decode_hex(&seed_hash[..64])?;

    Ok(seed_bytes
        .try_into()
        .expect("fixture seed hash prefix is 32 bytes"))
}

#[cfg(test)]
fn key_fixture_seed(seed_label: &str) -> CanonicalResult<[u8; 32]> {
    let seed_hash = derive_canonical_object_hash(&json!({
        "objectType": "MlDsaKeyFixtureSeed",
        "purpose": "ml-dsa-key-fixture-seed",
        "seedLabel": seed_label,
    }))?;
    let seed_bytes = decode_hex(&seed_hash[..64])?;

    Ok(seed_bytes
        .try_into()
        .expect("fixture key seed hash prefix is 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::{
        ProtocolSignatureExpectation, create_protocol_signature_fixture,
        verify_protocol_signature_envelope,
    };
    use crate::hashing::derive_canonical_object_hash;
    use serde_json::json;

    #[test]
    fn verifies_ml_dsa_signature_envelope_against_bound_root() {
        let object_root = derive_canonical_object_hash(&json!({
            "objectType": "ProtocolSignatureTestObject",
            "fixture": "signed-object",
        }))
        .expect("object root");
        let context_hash = derive_canonical_object_hash(&json!({
            "objectType": "ProtocolSignatureTestObject",
            "fixture": "signature-context",
        }))
        .expect("context hash");
        let signed_root = json!({
            "objectType": "SetupPhaseParticipantObject",
            "ceremonyId": "ceremony-main",
            "manifestHash": object_root,
            "boardHeadHash": null,
            "objectRoot": object_root,
            "chunkMerkleRoot": null,
            "signerRole": "Trustee",
            "signerIdentity": "trustee-0",
            "recoveryEpoch": 0,
            "deviceEpoch": 0,
            "contextHash": context_hash,
        });
        let fixture =
            create_protocol_signature_fixture("trustee-0", signed_root).expect("signature fixture");
        let expectation = ProtocolSignatureExpectation {
            object_type: "SetupPhaseParticipantObject",
            signer_role: "Trustee",
            signer_identity: "trustee-0",
            ceremony_id: "ceremony-main",
            public_key_hash: &fixture.public_key_hash,
            manifest_hash: Some(&object_root),
            object_root: Some(&object_root),
            chunk_merkle_root: None,
            board_head_hash: None,
            context_hash: &context_hash,
            recovery_epoch: 0,
            device_epoch: 0,
        };

        let signature_hash = verify_protocol_signature_envelope(&fixture.envelope, &expectation)
            .expect("verification should run")
            .expect("signature should verify");

        assert_eq!(signature_hash, fixture.envelope["signatureHash"]);
    }

    #[test]
    fn rejects_tampered_signed_root_after_hash_rebinding() {
        let object_root = derive_canonical_object_hash(&json!({
            "objectType": "ProtocolSignatureTestObject",
            "fixture": "signed-object",
        }))
        .expect("object root");
        let context_hash = derive_canonical_object_hash(&json!({
            "objectType": "ProtocolSignatureTestObject",
            "fixture": "signature-context",
        }))
        .expect("context hash");
        let signed_root = json!({
            "objectType": "SetupPhaseParticipantObject",
            "ceremonyId": "ceremony-main",
            "manifestHash": object_root,
            "boardHeadHash": null,
            "objectRoot": object_root,
            "chunkMerkleRoot": null,
            "signerRole": "Trustee",
            "signerIdentity": "trustee-0",
            "recoveryEpoch": 0,
            "deviceEpoch": 0,
            "contextHash": context_hash,
        });
        let fixture =
            create_protocol_signature_fixture("trustee-0", signed_root).expect("signature fixture");
        let mut tampered_envelope = fixture.envelope.clone();
        tampered_envelope["signedRoot"]["byteLength"] = json!(38);
        tampered_envelope["signatureHash"] = json!(
            super::derive_protocol_signature_hash(&tampered_envelope)
                .expect("signature hash should derive")
        );
        let expectation = ProtocolSignatureExpectation {
            object_type: "SetupPhaseParticipantObject",
            signer_role: "Trustee",
            signer_identity: "trustee-0",
            ceremony_id: "ceremony-main",
            public_key_hash: &fixture.public_key_hash,
            manifest_hash: Some(&object_root),
            object_root: Some(&object_root),
            chunk_merkle_root: None,
            board_head_hash: None,
            context_hash: &context_hash,
            recovery_epoch: 0,
            device_epoch: 0,
        };

        let failure = verify_protocol_signature_envelope(&tampered_envelope, &expectation)
            .expect("verification should run")
            .expect_err("tampered signature should not verify");

        assert_eq!(failure.reason_code, "InvalidSignature");
    }
}
