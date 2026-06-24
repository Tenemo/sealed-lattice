use super::*;

pub(in super::super) struct PublicKeyCommonBinding {
    pub(in super::super) public_matrix_seed_hash: String,
    pub(in super::super) public_key_crp_root: String,
    pub(in super::super) public_a_polynomial_root: String,
}

pub(super) struct PublicKeyShareBinding {
    pub(super) trustee_identity: String,
    pub(super) trustee_roster_position: u64,
    pub(super) public_key_share_root: String,
    pub(super) trustee_secret_commitment_root: String,
    pub(super) same_secret_statement_root: String,
}

pub(in super::super) fn public_key_common_binding(
    setup_package: &Value,
) -> CanonicalResult<PublicKeyCommonBinding> {
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before public-key share verification",
        )
    })?;
    let public_derivations = common_randomness.get("publicDerivations").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness.publicDerivations was required before public-key share verification",
        )
    })?;
    Ok(PublicKeyCommonBinding {
        public_matrix_seed_hash: value_string(common_randomness, "publicMatrixSeedHash")?
            .to_string(),
        public_key_crp_root: public_derivations
            .get("crpRoots")
            .and_then(|crp_roots| crp_roots.get("publicKeyCrpRoot"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "public-key CRP root was required before public-key share verification",
                )
            })?
            .to_string(),
        public_a_polynomial_root: public_derivations
            .get("bgvPublicA")
            .and_then(|public_a| public_a.get("publicPolynomialRoot"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "BGV public a root was required before public-key share verification",
                )
            })?
            .to_string(),
    })
}

#[derive(Clone, Copy)]
pub(super) enum PublicKeyRefusalKind {
    Share,
    Proof,
}

pub(super) fn verify_public_key_common_fields(
    value: &Value,
    common_binding: &PublicKeyCommonBinding,
    object_path: &str,
    refusal_kind: PublicKeyRefusalKind,
) -> CanonicalResult<Option<Value>> {
    for (field_name, expected_value) in [
        (
            "publicMatrixSeedHash",
            common_binding.public_matrix_seed_hash.as_str(),
        ),
        (
            "publicKeyCrpRoot",
            common_binding.public_key_crp_root.as_str(),
        ),
        (
            "publicAPolynomialRoot",
            common_binding.public_a_polynomial_root.as_str(),
        ),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            let message =
                format!("{object_path}.{field_name} must match accepted common randomness");
            let path = format!("setupPackage.{object_path}.{field_name}");
            return Ok(Some(match refusal_kind {
                PublicKeyRefusalKind::Share => {
                    public_key_share_refusal("publicKeyShareCommonBindingMismatch", message, path)?
                }
                PublicKeyRefusalKind::Proof => public_key_share_proof_refusal(
                    "publicKeyShareCommonBindingMismatch",
                    message,
                    path,
                )?,
            }));
        }
    }

    Ok(None)
}

pub(super) fn public_key_share_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("publicKeyShareProofs"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

pub(in super::super) fn public_key_share_proof_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("publicKeyShareProofs"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

pub(super) fn public_key_share_succinct_proof_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("publicKeyShareProofs"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
