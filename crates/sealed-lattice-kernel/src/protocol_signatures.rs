#[cfg(test)]
use fips204::traits::{KeyGen, Signer};
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};
use serde_json::{Map, Value, json};

#[cfg(test)]
use crate::encoding::{CanonicalError, CanonicalErrorCode};
use crate::{
    encoding::CanonicalResult,
    hashing::{canonical_json, derive_canonical_object_hash},
    transcript_core::decode_hex,
};

const PROTOCOL_SIGNATURE_MESSAGE_DOMAIN: &str = "sealed-lattice/protocol-signature";
const SUPPORTED_ML_DSA_CONTEXT_STRING: &str = "sealed-lattice:v1";

#[derive(Debug)]
pub(crate) struct ProtocolSignatureExpectation<'a> {
    pub object_type: &'a str,
    pub public_key_hash: &'a str,
    pub object_root: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProtocolSignatureFailure {
    pub reason_code: &'static str,
    pub message: String,
}

impl ProtocolSignatureFailure {
    fn new(reason_code: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason_code,
            message: message.into(),
        }
    }
}

#[derive(Debug)]
struct ParsedProtocolSignature<'a> {
    public_key_bytes: [u8; ml_dsa_65::PK_LEN],
    public_key_hash: &'a str,
    signature_bytes: [u8; ml_dsa_65::SIG_LEN],
    signed_root: ParsedSignedRoot<'a>,
}

#[derive(Clone, Copy, Debug)]
struct ParsedSignedRoot<'a> {
    object_type: &'a str,
    object_root: &'a str,
}

impl ParsedSignedRoot<'_> {
    fn wire_value(&self) -> Value {
        let mut signed_root = Map::new();
        signed_root.insert("objectType".into(), self.object_type.into());
        signed_root.insert("objectRoot".into(), self.object_root.into());
        Value::Object(signed_root)
    }
}

pub(crate) fn verify_protocol_signature_envelope(
    signature: &Value,
    expectation: &ProtocolSignatureExpectation<'_>,
) -> CanonicalResult<Result<(), ProtocolSignatureFailure>> {
    let parsed_signature = match parse_protocol_signature(signature)? {
        Ok(parsed_signature) => parsed_signature,
        Err(failure) => return Ok(Err(failure)),
    };
    if let Some(failure) = validate_expectation(&parsed_signature, expectation) {
        return Ok(Err(failure));
    }
    if let Some(failure) = verify_ml_dsa_signature(&parsed_signature)? {
        return Ok(Err(failure));
    }

    Ok(Ok(()))
}

fn parse_protocol_signature(
    signature: &Value,
) -> CanonicalResult<Result<ParsedProtocolSignature<'_>, ProtocolSignatureFailure>> {
    if !signature.is_object() {
        return Ok(Err(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Signature envelope must be a JSON object.",
        )));
    }
    let Some(public_key_bytes_hex) = signature.get("publicKeyBytesHex").and_then(Value::as_str)
    else {
        return Ok(Err(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Signature envelope must bind publicKeyBytesHex.",
        )));
    };
    let Some(public_key_hash) = signature.get("publicKeyHash").and_then(Value::as_str) else {
        return Ok(Err(ProtocolSignatureFailure::new(
            "WrongPublicKey",
            "Signature envelope must bind publicKeyHash.",
        )));
    };
    let Some(signature_bytes_hex) = signature.get("signatureBytesHex").and_then(Value::as_str)
    else {
        return Ok(Err(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Signature envelope must bind signatureBytesHex.",
        )));
    };

    let (Ok(public_key_bytes), Ok(signature_bytes)) = (
        decode_hex_array(public_key_bytes_hex),
        decode_hex_array(signature_bytes_hex),
    ) else {
        return Ok(Err(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "Signature envelope contains malformed ML-DSA key or signature bytes.",
        )));
    };
    if !is_protocol_hash_string(public_key_hash) {
        return Ok(Err(ProtocolSignatureFailure::new(
            "WrongPublicKey",
            "Signature public key hash must be a canonical protocol hash.",
        )));
    }

    let expected_public_key_hash = derive_ml_dsa_public_key_hash(public_key_bytes_hex)?;
    if public_key_hash != expected_public_key_hash {
        return Ok(Err(ProtocolSignatureFailure::new(
            "WrongPublicKey",
            "Signature public key hash does not match the ML-DSA public key bytes.",
        )));
    }

    let signed_root = match parse_signed_root(signature.get("signedRoot")) {
        Ok(signed_root) => signed_root,
        Err(failure) => return Ok(Err(failure)),
    };

    Ok(Ok(ParsedProtocolSignature {
        public_key_bytes,
        public_key_hash,
        signature_bytes,
        signed_root,
    }))
}

fn parse_signed_root(
    signed_root: Option<&Value>,
) -> Result<ParsedSignedRoot<'_>, ProtocolSignatureFailure> {
    let Some(signed_root) = signed_root.and_then(Value::as_object) else {
        return Err(ProtocolSignatureFailure::new(
            "InvalidSignedRoot",
            "Signature envelope must include a signedRoot object.",
        ));
    };

    let object_type = required_nonempty_string(signed_root, "objectType")?;
    let object_root = required_hash(signed_root, "objectRoot")?;

    Ok(ParsedSignedRoot {
        object_type,
        object_root,
    })
}

fn validate_expectation(
    signature: &ParsedProtocolSignature<'_>,
    expectation: &ProtocolSignatureExpectation<'_>,
) -> Option<ProtocolSignatureFailure> {
    let signed_root = &signature.signed_root;

    if signed_root.object_type != expectation.object_type {
        return Some(ProtocolSignatureFailure::new(
            "WrongObjectType",
            "Signature root object type does not match the expected object.",
        ));
    }
    if signature.public_key_hash != expectation.public_key_hash {
        return Some(ProtocolSignatureFailure::new(
            "WrongPublicKey",
            "Signature public key hash does not match the expected key.",
        ));
    }

    if signed_root.object_root != expectation.object_root {
        return Some(ProtocolSignatureFailure::new(
            "InvalidSignedRoot",
            "Signature root objectRoot does not match the expected binding.",
        ));
    }

    None
}

fn verify_ml_dsa_signature(
    signature: &ParsedProtocolSignature<'_>,
) -> CanonicalResult<Option<ProtocolSignatureFailure>> {
    let Ok(public_key) = ml_dsa_65::PublicKey::try_from_bytes(signature.public_key_bytes) else {
        return Ok(Some(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "ML-DSA public key bytes are not accepted by the verifier.",
        )));
    };
    let message =
        canonical_protocol_signature_message(signature.public_key_hash, &signature.signed_root)?;
    if !public_key.verify(
        message.as_bytes(),
        &signature.signature_bytes,
        SUPPORTED_ML_DSA_CONTEXT_STRING.as_bytes(),
    ) {
        return Ok(Some(ProtocolSignatureFailure::new(
            "InvalidSignature",
            "ML-DSA signature does not verify for the canonical signed root.",
        )));
    }

    Ok(None)
}

fn canonical_protocol_signature_message(
    public_key_hash: &str,
    signed_root: &ParsedSignedRoot<'_>,
) -> CanonicalResult<String> {
    canonical_json(&json!({
        "messageDomain": PROTOCOL_SIGNATURE_MESSAGE_DOMAIN,
        "publicKeyHash": public_key_hash,
        "signedRoot": signed_root.wire_value(),
    }))
}

fn derive_ml_dsa_public_key_hash(public_key_bytes_hex: &str) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "MlDsa65PublicKeyHash",
        "publicKeyBytesHex": public_key_bytes_hex,
    }))
}

fn decode_hex_array<const BYTE_LENGTH: usize>(value: &str) -> Result<[u8; BYTE_LENGTH], ()> {
    let bytes = decode_hex(value).map_err(|_| ())?;
    bytes.try_into().map_err(|_| ())
}

fn is_protocol_hash_string(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn required_nonempty_string<'a>(
    signed_root: &'a Map<String, Value>,
    field_name: &str,
) -> Result<&'a str, ProtocolSignatureFailure> {
    signed_root
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ProtocolSignatureFailure::new(
                "InvalidSignedRoot",
                format!("Signed roots must bind non-empty {field_name}."),
            )
        })
}

fn required_hash<'a>(
    signed_root: &'a Map<String, Value>,
    field_name: &str,
) -> Result<&'a str, ProtocolSignatureFailure> {
    signed_root
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|value| is_protocol_hash_string(value))
        .ok_or_else(|| {
            ProtocolSignatureFailure::new(
                "InvalidSignedRoot",
                format!("Signed-root {field_name} must be a canonical hash string."),
            )
        })
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
    let parsed_signed_root = parse_signed_root(Some(&signed_root)).map_err(|failure| {
        CanonicalError::new(CanonicalErrorCode::InvalidFixture, failure.message)
    })?;
    let canonical_signed_root = parsed_signed_root.wire_value();
    let seed = key_fixture_seed(seed_label)?;
    let (public_key, private_key) = ml_dsa_65::KG::keygen_from_seed(&seed);
    let public_key_bytes_hex = crate::hashing::to_hex(&public_key.into_bytes());
    let public_key_hash = derive_ml_dsa_public_key_hash(&public_key_bytes_hex)?;
    let message = canonical_protocol_signature_message(&public_key_hash, &parsed_signed_root)?;
    let signature_seed = fixture_seed(
        "ml-dsa-signature-fixture-seed",
        seed_label,
        &canonical_signed_root,
    )?;
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
    let envelope = json!({
        "publicKeyBytesHex": public_key_bytes_hex,
        "publicKeyHash": public_key_hash,
        "signatureBytesHex": crate::hashing::to_hex(&signature_bytes),
        "signedRoot": canonical_signed_root,
    });

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
        let signed_root = json!({
            "objectType": "CollectiveBgvSetupIntentTrusteeRegistration",
            "objectRoot": object_root,
        });
        let fixture =
            create_protocol_signature_fixture("trustee-0", signed_root).expect("signature fixture");
        let expectation = ProtocolSignatureExpectation {
            object_type: "CollectiveBgvSetupIntentTrusteeRegistration",
            public_key_hash: &fixture.public_key_hash,
            object_root: &object_root,
        };

        verify_protocol_signature_envelope(&fixture.envelope, &expectation)
            .expect("verification should run")
            .expect("signature should verify");
    }

    #[test]
    fn rejects_signature_root_missing_object_binding() {
        let object_root = derive_canonical_object_hash(&json!({
            "objectType": "ProtocolSignatureTestObject",
            "fixture": "signed-object",
        }))
        .expect("object root");
        let fixture = create_protocol_signature_fixture(
            "trustee-0",
            json!({
                "objectType": "CollectiveBgvSetupIntentTrusteeRegistration",
                "objectRoot": object_root,
            }),
        )
        .expect("signature fixture");
        let expectation = ProtocolSignatureExpectation {
            object_type: "CollectiveBgvSetupIntentTrusteeRegistration",
            public_key_hash: &fixture.public_key_hash,
            object_root: &object_root,
        };

        let mut incomplete_envelope = fixture.envelope.clone();
        incomplete_envelope["signedRoot"]
            .as_object_mut()
            .expect("signed root object")
            .remove("objectRoot")
            .expect("required binding exists in fixture");

        let failure = verify_protocol_signature_envelope(&incomplete_envelope, &expectation)
            .expect("verification should run")
            .expect_err("missing required binding must be rejected");

        assert_eq!(failure.reason_code, "InvalidSignedRoot");
    }

    #[test]
    fn rejects_tampered_signed_root() {
        let object_root = derive_canonical_object_hash(&json!({
            "objectType": "ProtocolSignatureTestObject",
            "fixture": "signed-object",
        }))
        .expect("object root");
        let tampered_object_root = derive_canonical_object_hash(&json!({
            "objectType": "ProtocolSignatureTestObject",
            "fixture": "tampered-object",
        }))
        .expect("tampered object root");
        let signed_root = json!({
            "objectType": "CollectiveBgvSetupIntentTrusteeRegistration",
            "objectRoot": object_root,
        });
        let fixture =
            create_protocol_signature_fixture("trustee-0", signed_root).expect("signature fixture");
        let mut tampered_envelope = fixture.envelope.clone();
        tampered_envelope["signedRoot"]["objectRoot"] = json!(tampered_object_root);
        let expectation = ProtocolSignatureExpectation {
            object_type: "CollectiveBgvSetupIntentTrusteeRegistration",
            public_key_hash: &fixture.public_key_hash,
            object_root: &tampered_object_root,
        };

        let failure = verify_protocol_signature_envelope(&tampered_envelope, &expectation)
            .expect("verification should run")
            .expect_err("tampered signature should not verify");

        assert_eq!(failure.reason_code, "InvalidSignature");
    }
}
