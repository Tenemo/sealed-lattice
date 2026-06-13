use super::*;

use crate::bgv::coefficient_codec::coefficient_vector_hash512;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS,
    PUBLIC_KEY_SHARE_SUCCINCT_PROOF_VERIFICATION_STATUS,
};

// Canonical per-limb hash of a public-key share coefficient vector, bound into
// the public-key share records and the public-key share material records.
const PUBLIC_KEY_SHARE_COEFFICIENT_VECTOR_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/public-key-share-coefficient-vector-v1";

pub(in crate::bgv::setup) fn public_key_share_coefficient_vector_hash(
    coefficients: &[u64],
) -> String {
    coefficient_vector_hash512(coefficients, PUBLIC_KEY_SHARE_COEFFICIENT_VECTOR_HASH_DOMAIN)
}

#[derive(Clone)]
pub(super) struct PublicKeyShareMaterialBinding {
    trustee_identity: String,
    trustee_roster_position: u64,
    pub(super) public_key_share_root: String,
    pub(super) public_key_share_material_root: String,
    pub(super) coefficients_by_limb: Vec<Vec<u64>>,
}

pub(super) fn verify_collective_public_key_pair_consistency(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let has_collective_public_key = setup_package.get("collectivePublicKey").is_some();
    let has_collective_public_key_root = setup_package.get("collectivePublicKeyRoot").is_some();
    if has_collective_public_key != has_collective_public_key_root {
        let object_path = if has_collective_public_key_root {
            "setupPackage.collectivePublicKey"
        } else {
            "setupPackage.collectivePublicKeyRoot"
        };
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyMaterialBeforeProofVerification",
            "collective public-key material is not accepted unless the aggregate object and package root are both present and root-bound",
            object_path,
        )?));
    }

    Ok(None)
}

pub(super) fn verify_collective_public_key_material(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let aggregate_object = setup_package.get("collectivePublicKey");
    let aggregate_root = setup_package.get("collectivePublicKeyRoot");
    if aggregate_object.is_none() && aggregate_root.is_none() {
        return Ok(None);
    }
    let Some(aggregate_object) = aggregate_object else {
        return Ok(Some(public_key_share_proof_refusal(
            "publicKeyMaterialBeforeProofVerification",
            "collective public-key material is not accepted unless it is root-bound to verified public-key share material and succinct proof records",
            "setupPackage.collectivePublicKeyRoot",
        )?));
    };
    if !aggregate_object.is_object() {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyNotObject",
            "collectivePublicKey must be a root-bound object",
            "setupPackage.collectivePublicKey",
        )?));
    }
    if let Some(unexpected_field) = unexpected_collective_public_key_field(aggregate_object) {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyUnexpectedField",
            format!("collectivePublicKey contains unexpected field {unexpected_field}"),
            format!("setupPackage.collectivePublicKey.{unexpected_field}"),
        )?));
    }
    if aggregate_object.get("objectType").and_then(Value::as_str)
        != Some(COLLECTIVE_PUBLIC_KEY_OBJECT_TYPE)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyTypeMismatch",
            "collectivePublicKey.objectType must be CollectivePublicKey",
            "setupPackage.collectivePublicKey.objectType",
        )?));
    }
    if aggregate_object
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyVersionMismatch",
            "collectivePublicKey.objectVersion must be 1",
            "setupPackage.collectivePublicKey.objectVersion",
        )?));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before collective public-key verification",
        )
    })?;
    if let Err(error) = verify_same_secret_context(aggregate_object, setup_context) {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyContextMismatch",
            error.message,
            "setupPackage.collectivePublicKey",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
        (
            "proofVerificationStatus",
            PUBLIC_KEY_SHARE_SUCCINCT_PROOF_VERIFICATION_STATUS,
        ),
        ("proofModelStatus", PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS),
        (
            "aggregationStatus",
            "succinct-proof-aggregated-with-accepted-setup-proof-accounting",
        ),
        (
            "materialEncoding",
            "embedded-full-collective-public-key-coefficients",
        ),
    ] {
        if aggregate_object.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(public_key_share_proof_refusal(
                "collectivePublicKeyProfileMismatch",
                format!("collectivePublicKey.{field_name} must be {expected_value}"),
                format!("setupPackage.collectivePublicKey.{field_name}"),
            )?));
        }
    }
    let material_set = setup_package.get("publicKeyShareMaterial").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial was required before collective public-key verification",
        )
    })?;
    let succinct_proof_set = setup_package
        .get("publicKeyShareSuccinctProofs")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareSuccinctProofs was required before collective public-key verification",
            )
        })?;
    if public_key_share_material_uses_transport(material_set)
        && request.get("transportedPublicKeyShareMaterial").is_none()
    {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("setupPackageAssembly"),
            vec!["transportedPublicKeyShareMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    }
    let common_binding = public_key_common_binding(setup_package)?;
    let share_records = public_key_share_records_by_roster_position(setup_package)?;
    let material_bindings = match verify_public_key_share_material_set(
        material_set,
        setup_context,
        &common_binding,
        value_string(
            setup_package.get("publicKeyShares").ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "publicKeyShares was required before collective public-key verification",
                )
            })?,
            "publicKeyShareSetRoot",
        )?,
        &share_records,
        request,
    ) {
        Ok(bindings) => bindings,
        Err(error) => {
            return Ok(Some(public_key_share_proof_refusal(
                "collectivePublicKeySourceMaterialVerificationFailed",
                error.message,
                "setupPackage.publicKeyShareMaterial",
            )?));
        }
    };
    let ring_degree = value_u64(aggregate_object, "ringDegree")?;
    if ring_degree == 0
        || ring_degree > POLYNOMIAL_DEGREE as u64
        || aggregate_object
            .get("participantCount")
            .and_then(Value::as_u64)
            != Some(FIRST_PROFILE_PARTICIPANT_COUNT)
        || aggregate_object.get("rnsLimbCount").and_then(Value::as_u64)
            != Some(DATA_PRIMES.len() as u64)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyProfileCountMismatch",
            "collectivePublicKey participant count, limb count, and ring degree must match the selected setup profile",
            "setupPackage.collectivePublicKey",
        )?));
    }
    let same_secret_consistency_root = same_secret_consistency_root_from_package(setup_package)?;
    let same_secret_proof_set_root = same_secret_proof_set_root_from_package(setup_package)?;
    let same_secret_proof_family_binding_root = same_secret_proof_family_binding_root()?;
    let expected_source_bindings = [
        (
            "publicMatrixSeedHash",
            Some(common_binding.public_matrix_seed_hash.as_str()),
        ),
        (
            "publicKeyCrpRoot",
            Some(common_binding.public_key_crp_root.as_str()),
        ),
        (
            "publicAPolynomialRoot",
            Some(common_binding.public_a_polynomial_root.as_str()),
        ),
        (
            "sameSecretConsistencyRoot",
            Some(same_secret_consistency_root.as_str()),
        ),
        (
            "sameSecretProofSetRoot",
            Some(same_secret_proof_set_root.as_str()),
        ),
        (
            "sameSecretProofFamilyBindingRoot",
            Some(same_secret_proof_family_binding_root.as_str()),
        ),
        (
            "publicKeyShareSetRoot",
            setup_package
                .get("publicKeyShares")
                .and_then(|share_set| share_set.get("publicKeyShareSetRoot"))
                .and_then(Value::as_str),
        ),
        (
            "publicKeyShareProofSetRoot",
            setup_package
                .get("publicKeyShareProofs")
                .and_then(|proof_set| proof_set.get("publicKeyShareProofSetRoot"))
                .and_then(Value::as_str),
        ),
        (
            "publicKeyShareMaterialSetRoot",
            material_set
                .get("publicKeyShareMaterialSetRoot")
                .and_then(Value::as_str),
        ),
        (
            "publicKeyShareSuccinctProofSetRoot",
            succinct_proof_set
                .get("publicKeyShareSuccinctProofSetRoot")
                .and_then(Value::as_str),
        ),
    ];
    for (field_name, expected_value) in expected_source_bindings {
        if aggregate_object.get(field_name).and_then(Value::as_str) != expected_value {
            return Ok(Some(public_key_share_proof_refusal(
                "collectivePublicKeySourceRootMismatch",
                format!("collectivePublicKey.{field_name} must bind the verified source root"),
                format!("setupPackage.collectivePublicKey.{field_name}"),
            )?));
        }
    }
    if let Err(error) = verify_collective_public_key_coefficients(
        aggregate_object,
        &material_bindings,
        usize::try_from(ring_degree).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "collective public-key ring degree does not fit usize",
            )
        })?,
    ) {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyVerificationFailed",
            error.message,
            "setupPackage.collectivePublicKey",
        )?));
    }
    let collective_public_key_root = value_string(aggregate_object, "collectivePublicKeyRoot")?;
    validate_hash_string(
        collective_public_key_root,
        "collectivePublicKey.collectivePublicKeyRoot",
    )?;
    if aggregate_root.and_then(Value::as_str) != Some(collective_public_key_root) {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyPackageRootMismatch",
            "setupPackage.collectivePublicKeyRoot must match collectivePublicKey.collectivePublicKeyRoot",
            "setupPackage.collectivePublicKeyRoot",
        )?));
    }
    let mut root_input = aggregate_object.clone();
    root_input
        .as_object_mut()
        .expect("collective public-key object was checked")
        .remove("collectivePublicKeyRoot");
    let expected_root = derive_protocol_hash("CollectivePublicKeyRoot", &root_input)?;
    if collective_public_key_root != expected_root {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyRootMismatch",
            "collectivePublicKeyRoot does not match the canonical collective public key",
            "setupPackage.collectivePublicKey.collectivePublicKeyRoot",
        )?));
    }
    if ring_degree == POLYNOMIAL_DEGREE as u64
        && let Err(error) = accepted_setup_collective_public_key_from_package(setup_package)
    {
        return Ok(Some(public_key_share_proof_refusal(
            "collectivePublicKeyRuntimeMaterialInvalid",
            error.message,
            "setupPackage.collectivePublicKey",
        )?));
    }

    Ok(None)
}

pub(in crate::bgv::setup) fn accepted_setup_collective_public_key_from_package(
    setup_package: &Value,
) -> CanonicalResult<BgvPublicKey> {
    let aggregate_object = setup_package.get("collectivePublicKey").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "collectivePublicKey was required before accepted public-key runtime loading",
        )
    })?;
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before accepted public-key runtime loading",
        )
    })?;
    let public_matrix_seed_hash = value_string(common_randomness, "publicMatrixSeedHash")?;
    if value_string(aggregate_object, "publicMatrixSeedHash")? != public_matrix_seed_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key must bind the accepted public matrix seed",
        ));
    }
    let expected_public_derivations =
        derive_collective_bgv_setup_public_derivations(public_matrix_seed_hash)?;
    if common_randomness.get("publicDerivations") != Some(&expected_public_derivations) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted public-key runtime loading requires canonical public derivations",
        ));
    }
    let expected_public_a = derive_bgv_public_a_polynomial(public_matrix_seed_hash)?;
    if value_string(aggregate_object, "publicAPolynomialRoot")?
        != value_string(&expected_public_a, "publicPolynomialRoot")?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key must bind the accepted BGV public a polynomial",
        ));
    }
    if value_u64(aggregate_object, "ringDegree")? != POLYNOMIAL_DEGREE as u64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "accepted collective public-key runtime material requires profile-ring aggregate coefficients",
        ));
    }
    let public_b = collective_public_key_component_b_from_aggregate_object(aggregate_object)?;
    let public_a = DATA_PRIMES
        .iter()
        .copied()
        .map(|modulus| {
            dense_public_residues(public_matrix_seed_hash, "accepted-bgv-public-a", modulus)
        })
        .collect::<Vec<_>>();

    BgvPublicKey::from_components(public_b, public_a)
}

fn collective_public_key_component_b_from_aggregate_object(
    aggregate_object: &Value,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let aggregate_limbs = aggregate_object
        .get("aggregateCoefficientVectorsByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "collectivePublicKey.aggregateCoefficientVectorsByLimb is required",
            )
        })?;
    if aggregate_limbs.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key must contain one runtime component-b limb per Q_share prime",
        ));
    }
    let mut public_b = Vec::with_capacity(DATA_PRIMES.len());
    for (rns_limb_index, aggregate_limb) in aggregate_limbs.iter().enumerate() {
        if aggregate_limb.get("rnsLimbIndex").and_then(Value::as_u64) != Some(rns_limb_index as u64)
            || aggregate_limb.get("rnsPrime").and_then(Value::as_u64)
                != Some(DATA_PRIMES[rns_limb_index])
            || aggregate_limb.get("component").and_then(Value::as_str) != Some("b")
            || aggregate_limb
                .get("coefficientByteLength")
                .and_then(Value::as_u64)
                != Some((POLYNOMIAL_DEGREE * 8) as u64)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "collective public-key runtime limb metadata must follow Q_share order",
            ));
        }
        let coefficients = coefficient_vector_from_le_hex(
            value_string(aggregate_limb, "coefficientsLeHex")?,
            POLYNOMIAL_DEGREE,
            "collective public-key runtime coefficient vector width must match the profile ring degree",
        )?;
        if coefficients
            .iter()
            .any(|coefficient| *coefficient >= DATA_PRIMES[rns_limb_index])
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "collective public-key runtime component contains non-canonical Q_share residues",
            ));
        }
        let coefficient_hash = public_key_share_coefficient_vector_hash(&coefficients);
        if aggregate_limb
            .get("coefficientVectorHash512")
            .and_then(Value::as_str)
            != Some(coefficient_hash.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "collective public-key runtime component hash must match the aggregate coefficients",
            ));
        }
        public_b.push(coefficients);
    }

    Ok(public_b)
}

fn verify_collective_public_key_coefficients(
    aggregate_object: &Value,
    material_bindings: &BTreeMap<u64, PublicKeyShareMaterialBinding>,
    ring_degree: usize,
) -> CanonicalResult<()> {
    if material_bindings.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public-key aggregation requires one verified share material record per trustee",
        ));
    }
    let aggregate_limbs = aggregate_object
        .get("aggregateCoefficientVectorsByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "collectivePublicKey.aggregateCoefficientVectorsByLimb is required",
            )
        })?;
    if aggregate_limbs.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public key must contain one aggregate coefficient vector per Q_share limb",
        ));
    }
    let expected_share_material_roots = material_bindings
        .values()
        .map(|binding| {
            json!({
                "trusteeIdentity": binding.trustee_identity,
                "trusteeRosterPosition": binding.trustee_roster_position,
                "publicKeyShareRoot": binding.public_key_share_root,
                "publicKeyShareMaterialRoot": binding.public_key_share_material_root,
            })
        })
        .collect::<Vec<_>>();
    if aggregate_object.get("sourceShareMaterialRoots")
        != Some(&Value::Array(expected_share_material_roots))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "collective public key must bind the ordered verified share material roots",
        ));
    }
    for (rns_limb_index, aggregate_limb) in aggregate_limbs.iter().enumerate() {
        if aggregate_limb.get("rnsLimbIndex").and_then(Value::as_u64) != Some(rns_limb_index as u64)
            || aggregate_limb.get("rnsPrime").and_then(Value::as_u64)
                != Some(DATA_PRIMES[rns_limb_index])
            || aggregate_limb.get("component").and_then(Value::as_str) != Some("b")
            || aggregate_limb
                .get("coefficientByteLength")
                .and_then(Value::as_u64)
                != Some((ring_degree * 8) as u64)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "collective public-key aggregate limb metadata must follow Q_share order",
            ));
        }
        let coefficients = coefficient_vector_from_le_hex(
            value_string(aggregate_limb, "coefficientsLeHex")?,
            ring_degree,
            "collective public-key coefficient vector width does not match the material ring degree",
        )?;
        let modulus = DATA_PRIMES[rns_limb_index];
        let mut expected_coefficients = vec![0_u64; ring_degree];
        for material_binding in material_bindings.values() {
            let share_coefficients = material_binding
                .coefficients_by_limb
                .get(rns_limb_index)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public-key share material is missing an aggregate limb",
                    )
                })?;
            if share_coefficients.len() != ring_degree {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material width does not match collective public-key width",
                ));
            }
            for (coefficient_index, share_coefficient) in share_coefficients.iter().enumerate() {
                expected_coefficients[coefficient_index] = add_mod(
                    expected_coefficients[coefficient_index],
                    *share_coefficient,
                    modulus,
                )?;
            }
        }
        if coefficients != expected_coefficients {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "collective public-key aggregate coefficients must equal the sum of verified public-key shares",
            ));
        }
        let coefficient_hash = public_key_share_coefficient_vector_hash(&coefficients);
        if aggregate_limb
            .get("coefficientVectorHash512")
            .and_then(Value::as_str)
            != Some(coefficient_hash.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "collective public-key aggregate coefficient hash must match the aggregate coefficients",
            ));
        }
    }

    Ok(())
}

pub(super) fn public_key_share_material_uses_transport(material_set: &Value) -> bool {
    material_set.get("materialEncoding").and_then(Value::as_str)
        == Some(PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING)
}

fn verify_embedded_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
) -> CanonicalResult<(BTreeMap<u64, PublicKeyShareMaterialBinding>, Vec<Value>)> {
    if material_set.get("binaryFormat").is_some() || material_set.get("transport").is_some() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "embedded public-key share material must not declare binary transport fields",
        ));
    }
    let material_records = material_set
        .get("shareMaterialRecords")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareMaterial.shareMaterialRecords are required",
            )
        })?;
    if material_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "publicKeyShareMaterial.shareMaterialRecords must contain one record per trustee",
        ));
    }
    let mut bindings = BTreeMap::new();
    let mut material_roots = Vec::new();
    for material_record in material_records {
        let binding = verify_public_key_share_material_record(
            material_record,
            setup_context,
            common_binding,
            ring_degree,
            share_records,
        )?;
        if bindings
            .insert(binding.trustee_roster_position, binding.clone())
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "publicKeyShareMaterial.shareMaterialRecords contain duplicate roster positions",
            ));
        }
        material_roots.push(public_key_share_material_root_reference(&binding));
    }

    Ok((bindings, material_roots))
}

fn verify_transport_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
    request: &Value,
) -> CanonicalResult<(BTreeMap<u64, PublicKeyShareMaterialBinding>, Vec<Value>)> {
    if material_set.get("shareMaterialRecords").is_some() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "binary-chunked public-key share material must not embed shareMaterialRecords",
        ));
    }
    if material_set.get("binaryFormat").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_BINARY_FORMAT)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.binaryFormat must match the accepted public-key share material binary format",
        ));
    }
    let Some(transported_material) = request.get("transportedPublicKeyShareMaterial") else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial is required for binary-chunked public-key share material",
        ));
    };
    verify_public_key_share_material_transport_header(transported_material)?;
    let chunks = public_key_share_material_chunks(transported_material)?;
    let transport_hashes = public_key_share_material_transport_hashes(&chunks)?;
    verify_public_key_share_material_transport_hash_fields(
        transported_material,
        &transport_hashes,
        true,
        "transported public-key share material",
    )?;
    verify_public_key_share_material_set_transport_reference(material_set, &transport_hashes)?;
    let (bindings, material_roots) = decode_public_key_share_material_bindings(
        setup_context,
        common_binding,
        ring_degree,
        share_records,
        &chunks,
    )?;

    Ok((bindings, material_roots))
}

fn public_key_share_material_root_reference(binding: &PublicKeyShareMaterialBinding) -> Value {
    json!({
        "trusteeIdentity": binding.trustee_identity,
        "trusteeRosterPosition": binding.trustee_roster_position,
        "publicKeyShareMaterialRoot": binding.public_key_share_material_root,
    })
}

#[derive(Debug)]
pub(in crate::bgv::setup) struct PublicKeyShareMaterialTransportHashes {
    pub(in crate::bgv::setup) full_object_hash: String,
    pub(in crate::bgv::setup) chunk_hashes: Vec<String>,
    pub(in crate::bgv::setup) chunk_root: String,
    pub(in crate::bgv::setup) total_byte_length: u64,
}

struct PublicKeyShareMaterialByteReader {
    bytes: Vec<u8>,
    offset: usize,
}

impl PublicKeyShareMaterialByteReader {
    fn new(chunks: &[Vec<u8>]) -> CanonicalResult<Self> {
        let total_byte_length = chunks.iter().try_fold(0_usize, |byte_count, chunk| {
            byte_count.checked_add(chunk.len()).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material byte length overflowed",
                )
            })
        })?;
        let mut bytes = Vec::with_capacity(total_byte_length);
        for chunk in chunks {
            bytes.extend_from_slice(chunk);
        }

        Ok(Self { bytes, offset: 0 })
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_exact(&mut self, length: usize) -> CanonicalResult<&[u8]> {
        let end_offset = self.offset.checked_add(length).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material read offset overflowed",
            )
        })?;
        let Some(slice) = self.bytes.get(self.offset..end_offset) else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "transported public-key share material ended before the binary object was complete",
            ));
        };
        self.offset = end_offset;

        Ok(slice)
    }

    fn read_varuint(&mut self, field_name: &str) -> CanonicalResult<u64> {
        let mut shift = 0_u32;
        let mut value = 0_u64;
        let mut consumed = Vec::new();
        for byte_index in 0..10 {
            let byte = self.read_exact(1)?[0];
            consumed.push(byte);
            let payload = u64::from(byte & 0x7f);
            if byte_index == 9 && payload > 1 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    format!("{field_name} binary varuint exceeds u64"),
                ));
            }
            value |= payload << shift;
            if byte & 0x80 == 0 {
                let mut canonical = Vec::new();
                crate::encoding::append_varuint(&mut canonical, value);
                if canonical != consumed {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{field_name} binary varuint is not minimally encoded"),
                    ));
                }

                return Ok(value);
            }
            shift += 7;
        }

        Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} binary varuint is too long"),
        ))
    }

    fn read_u64_le(&mut self, field_name: &str) -> CanonicalResult<u64> {
        let bytes = self.read_exact(8)?;
        let byte_array: [u8; 8] = bytes.try_into().map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{field_name} is malformed"),
            )
        })?;

        Ok(u64::from_le_bytes(byte_array))
    }
}

fn verify_public_key_share_material_transport_header(value: &Value) -> CanonicalResult<()> {
    let Some(object) = value.as_object() else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial must be an object",
        ));
    };
    for field_name in object.keys() {
        if ![
            "objectType",
            "objectVersion",
            "binaryFormat",
            "chunkSizeBytes",
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkHashes",
            "chunkRoot",
            "chunks",
        ]
        .contains(&field_name.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("transportedPublicKeyShareMaterial contains unexpected field {field_name}"),
            ));
        }
    }
    if value.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial.objectType must be SetupTransportedPublicKeyShareMaterial",
        ));
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial.objectVersion must be 1",
        ));
    }
    if value.get("binaryFormat").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_BINARY_FORMAT)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial.binaryFormat must match the accepted public-key share material binary format",
        ));
    }

    Ok(())
}

fn public_key_share_material_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    if value_u64(value, "chunkSizeBytes")? != SETUP_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key share material chunkSizeBytes must match the setup transport profile",
        ));
    }
    let expected_chunk_count = usize::try_from(value_u64(value, "chunkCount")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key share material chunkCount does not fit usize",
        )
    })?;
    let chunk_values = array_value(value, "chunks")?;
    if chunk_values.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key share material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(expected_chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        if value_u64(chunk_value, "chunkIndex")?
            != u64::try_from(expected_chunk_index).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material chunk index does not fit u64",
                )
            })?
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key share material chunks must be in ascending chunk-index order",
            ));
        }
        chunks.push(decode_hex(value_string(chunk_value, "bytesHex")?)?);
    }

    Ok(chunks)
}

pub(in crate::bgv::setup) fn public_key_share_material_transport_hashes(
    chunks: &[Vec<u8>],
) -> CanonicalResult<PublicKeyShareMaterialTransportHashes> {
    if chunks.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material transport requires at least one chunk",
        ));
    }
    let chunk_size = usize::try_from(SETUP_TRANSPORT_CHUNK_SIZE_BYTES).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup transport chunk size does not fit usize",
        )
    })?;
    let total_byte_length =
        chunks
            .iter()
            .enumerate()
            .try_fold(0_u64, |byte_count, (chunk_index, chunk)| {
                if chunk.is_empty() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public-key share material chunks must be non-empty",
                    ));
                }
                if chunk.len() > chunk_size {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public-key share material chunk exceeds the accepted chunk size",
                    ));
                }
                if chunk_index + 1 < chunks.len() && chunk.len() != chunk_size {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public-key share material contains a short non-final chunk",
                    ));
                }
                byte_count
                    .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "public-key share material chunk length does not fit u64",
                        )
                    })?)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "public-key share material byte length overflowed",
                        )
                    })
            })?;
    let full_object_hash = public_key_share_material_full_object_hash(total_byte_length, chunks);
    let chunk_hashes = chunks
        .iter()
        .enumerate()
        .map(|(chunk_index, chunk)| {
            public_key_share_material_chunk_hash(&full_object_hash, chunk_index, chunk)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let chunk_root = setup_transport_chunk_manifest_root(
        SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        u64::try_from(chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material chunk count does not fit u64",
            )
        })?,
        total_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;

    Ok(PublicKeyShareMaterialTransportHashes {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        total_byte_length,
    })
}

fn public_key_share_material_full_object_hash(
    total_byte_length: u64,
    chunks: &[Vec<u8>],
) -> String {
    let total_length_bytes = total_byte_length.to_le_bytes();
    let mut parts = Vec::with_capacity(chunks.len() + 1);
    parts.push(total_length_bytes.as_slice());
    for chunk in chunks {
        parts.push(chunk.as_slice());
    }

    hash512_hex(
        "sealed-lattice/setup/public-key-share-material/full-object-v1",
        &parts,
    )
}

fn public_key_share_material_chunk_hash(
    full_object_hash: &str,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    let chunk_index_bytes = u64::try_from(chunk_index)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material chunk index does not fit u64",
            )
        })?
        .to_le_bytes();

    Ok(hash512_hex(
        "sealed-lattice/setup/public-key-share-material/chunk-v1",
        &[full_object_hash.as_bytes(), &chunk_index_bytes, chunk],
    ))
}

fn verify_public_key_share_material_transport_hash_fields(
    value: &Value,
    transport_hashes: &PublicKeyShareMaterialTransportHashes,
    require_chunk_hashes: bool,
    value_name: &str,
) -> CanonicalResult<()> {
    let chunk_size = value_u64(value, "chunkSizeBytes")?;
    let chunk_count = value_u64(value, "chunkCount")?;
    let total_byte_length = value_u64(value, "totalByteLength")?;
    let full_object_hash = value_string(value, "fullObjectHash")?;
    let chunk_root = value_string(value, "chunkRoot")?;
    if chunk_size != SETUP_TRANSPORT_CHUNK_SIZE_BYTES
        || chunk_count
            != u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material chunk count does not fit u64",
                )
            })?
        || total_byte_length != transport_hashes.total_byte_length
        || full_object_hash != transport_hashes.full_object_hash
        || chunk_root != transport_hashes.chunk_root
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{value_name} hash metadata does not match supplied chunks"),
        ));
    }
    if require_chunk_hashes {
        let chunk_hash_values = value
            .get("chunkHashes")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{value_name} must list every public-key share material chunk hash"),
                )
            })?;
        if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{value_name} chunk hash count must match supplied chunks"),
            ));
        }
        for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
            .iter()
            .zip(transport_hashes.chunk_hashes.iter())
        {
            if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{value_name} chunk hashes must match supplied chunks"),
                ));
            }
        }
    }

    Ok(())
}

fn verify_public_key_share_material_set_transport_reference(
    material_set: &Value,
    transport_hashes: &PublicKeyShareMaterialTransportHashes,
) -> CanonicalResult<()> {
    let transport = material_set.get("transport").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.transport is required for binary-chunked material",
        )
    })?;
    let Some(transport_object) = transport.as_object() else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.transport must be an object",
        ));
    };
    for field_name in transport_object.keys() {
        if ![
            "transportProfileId",
            "chunkSizeBytes",
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkRoot",
        ]
        .contains(&field_name.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("publicKeyShareMaterial.transport contains unexpected field {field_name}"),
            ));
        }
    }
    if transport.get("transportProfileId").and_then(Value::as_str)
        != Some(SETUP_TRANSPORT_PROFILE_ID)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.transport.transportProfileId must match the setup transport profile",
        ));
    }
    verify_public_key_share_material_transport_hash_fields(
        transport,
        transport_hashes,
        false,
        "public-key share material transport reference",
    )
}

fn decode_public_key_share_material_bindings(
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
    chunks: &[Vec<u8>],
) -> CanonicalResult<(BTreeMap<u64, PublicKeyShareMaterialBinding>, Vec<Value>)> {
    let mut reader = PublicKeyShareMaterialByteReader::new(chunks)?;
    let magic = reader.read_exact(PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC.len())?;
    if magic != PUBLIC_KEY_SHARE_MATERIAL_BINARY_MAGIC {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share material binary magic does not match",
        ));
    }
    if reader.read_varuint("binary version")? != PUBLIC_KEY_SHARE_MATERIAL_BINARY_VERSION {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share material binary version is unsupported",
        ));
    }
    if reader.read_varuint("participantCount")? != FIRST_PROFILE_PARTICIPANT_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "transported public-key share material participant count does not match the accepted profile",
        ));
    }
    if reader.read_varuint("rnsLimbCount")? != DATA_PRIMES.len() as u64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "transported public-key share material RNS limb count does not match Q_share",
        ));
    }
    if usize::try_from(reader.read_varuint("ringDegree")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key share material ringDegree does not fit usize",
        )
    })? != ring_degree
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "transported public-key share material ring degree must match the material set",
        ));
    }

    let mut bindings = BTreeMap::new();
    let mut material_roots = Vec::new();
    for expected_roster_position in 0..FIRST_PROFILE_PARTICIPANT_COUNT {
        if reader.read_varuint("trusteeRosterPosition")? != expected_roster_position {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key share material trustee order is not canonical",
            ));
        }
        let share_record = share_records
            .get(&expected_roster_position)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "transported public-key share material must reference an accepted share record",
                )
            })?;
        let trustee_identity = value_string(share_record, "trusteeIdentity")?.to_string();
        let public_key_share_root = value_string(share_record, "publicKeyShareRoot")?.to_string();
        let share_hashes = share_record
            .get("shareCoefficientVectorHash512ByLimb")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "accepted public-key share hashes are required",
                )
            })?;
        let mut coefficients_by_limb = Vec::with_capacity(DATA_PRIMES.len());
        let mut limb_records = Vec::with_capacity(DATA_PRIMES.len());
        for (rns_limb_index, modulus) in DATA_PRIMES.iter().copied().enumerate() {
            if reader.read_varuint("rnsLimbIndex")? != rns_limb_index as u64 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "transported public-key share material RNS limb order is not canonical",
                ));
            }
            if reader.read_u64_le("rnsPrime")? != modulus {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "transported public-key share material RNS prime does not match Q_share",
                ));
            }
            let mut coefficients = Vec::with_capacity(ring_degree);
            for _coefficient_index in 0..ring_degree {
                let coefficient = reader.read_u64_le("public-key share coefficient")?;
                if coefficient >= modulus {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        "transported public-key share coefficient is not a canonical residue",
                    ));
                }
                coefficients.push(coefficient);
            }
            let coefficient_hash = public_key_share_coefficient_vector_hash(&coefficients);
            if share_hashes
                .get(rns_limb_index)
                .and_then(|share_hash| share_hash.get("rnsLimbIndex"))
                .and_then(Value::as_u64)
                != Some(rns_limb_index as u64)
                || share_hashes
                    .get(rns_limb_index)
                    .and_then(|share_hash| share_hash.get("rnsPrime"))
                    .and_then(Value::as_u64)
                    != Some(modulus)
                || share_hashes
                    .get(rns_limb_index)
                    .and_then(|share_hash| share_hash.get("component"))
                    .and_then(Value::as_str)
                    != Some("b_i")
                || share_hashes
                    .get(rns_limb_index)
                    .and_then(|share_hash| share_hash.get("coefficientVectorHash512"))
                    .and_then(Value::as_str)
                    != Some(coefficient_hash.as_str())
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "transported public-key share coefficient hash must match the accepted share record",
                ));
            }
            limb_records.push(json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": modulus,
                "component": "b_i",
                "coefficientByteLength": ring_degree * 8,
                "coefficientVectorHash512": coefficient_hash,
                "coefficientsLeHex": coefficient_vector_le_hex(&coefficients),
            }));
            coefficients_by_limb.push(coefficients);
        }
        let material_record = json!({
            "objectType": PUBLIC_KEY_SHARE_MATERIAL_OBJECT_TYPE,
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": "public-key-share",
            "proofModelStatus": PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS,
            "materialEncoding": PUBLIC_KEY_SHARE_MATERIAL_EMBEDDED_ENCODING,
            "ceremonyId": value_string(setup_context, "ceremonyId")?,
            "manifestHash": value_string(setup_context, "manifestHash")?,
            "rosterHash": value_string(setup_context, "rosterHash")?,
            "setupProfileHash": value_string(setup_context, "setupProfileHash")?,
            "qShareHash": value_string(setup_context, "qShareHash")?,
            "carryAwareVssShareRelationProfileHash": value_string(
                setup_context,
                "carryAwareVssShareRelationProfileHash",
            )?,
            "commitmentProfileHash": value_string(setup_context, "commitmentProfileHash")?,
            "setupEpoch": value_string(setup_context, "setupEpoch")?,
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": expected_roster_position,
            "rnsLimbCount": DATA_PRIMES.len(),
            "ringDegree": ring_degree,
            "publicMatrixSeedHash": common_binding.public_matrix_seed_hash,
            "publicKeyCrpRoot": common_binding.public_key_crp_root,
            "publicAPolynomialRoot": common_binding.public_a_polynomial_root,
            "publicKeyShareRoot": public_key_share_root,
            "shareCoefficientVectorsByLimb": limb_records,
        });
        let public_key_share_material_root =
            derive_protocol_hash("PublicKeyShareRoot", &material_record)?;
        let binding = PublicKeyShareMaterialBinding {
            trustee_identity: value_string(&material_record, "trusteeIdentity")?.to_string(),
            trustee_roster_position: expected_roster_position,
            public_key_share_root: value_string(&material_record, "publicKeyShareRoot")?
                .to_string(),
            public_key_share_material_root,
            coefficients_by_limb,
        };
        material_roots.push(public_key_share_material_root_reference(&binding));
        if bindings
            .insert(binding.trustee_roster_position, binding)
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key share material contains duplicate trustee records",
            ));
        }
    }
    if !reader.is_finished() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported public-key share material has trailing bytes after the final trustee record",
        ));
    }

    Ok((bindings, material_roots))
}

pub(super) fn verify_public_key_share_material_set(
    material_set: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    public_key_share_set_root: &str,
    share_records: &BTreeMap<u64, Value>,
    request: &Value,
) -> CanonicalResult<BTreeMap<u64, PublicKeyShareMaterialBinding>> {
    if !material_set.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial must be a root-bound object",
        ));
    }
    if let Some(unexpected_field) = unexpected_public_key_share_material_set_field(material_set) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("publicKeyShareMaterial contains unexpected field {unexpected_field}"),
        ));
    }
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_SET_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.objectType must be PublicKeyShareMaterialSet",
        ));
    }
    if material_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.objectVersion must be 1",
        ));
    }
    verify_same_secret_context(material_set, setup_context)?;
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
        ("proofModelStatus", PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS),
    ] {
        if material_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("publicKeyShareMaterial.{field_name} must be {expected_value}"),
            ));
        }
    }
    let material_encoding = value_string(material_set, "materialEncoding")?;
    if ![
        PUBLIC_KEY_SHARE_MATERIAL_EMBEDDED_ENCODING,
        PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_ENCODING,
    ]
    .contains(&material_encoding)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.materialEncoding must be embedded full public-key share coefficients or binary-chunked full public-key share coefficients",
        ));
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if material_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("publicKeyShareMaterial.{field_name} must be {expected_value}"),
            ));
        }
    }
    let ring_degree = usize::try_from(value_u64(material_set, "ringDegree")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "publicKeyShareMaterial.ringDegree does not fit usize",
        )
    })?;
    if ring_degree == 0 || ring_degree > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "publicKeyShareMaterial.ringDegree is outside the selected profile",
        ));
    }
    if material_set
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(common_binding.public_matrix_seed_hash.as_str())
        || material_set.get("publicKeyCrpRoot").and_then(Value::as_str)
            != Some(common_binding.public_key_crp_root.as_str())
        || material_set
            .get("publicAPolynomialRoot")
            .and_then(Value::as_str)
            != Some(common_binding.public_a_polynomial_root.as_str())
        || material_set
            .get("publicKeyShareSetRoot")
            .and_then(Value::as_str)
            != Some(public_key_share_set_root)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "publicKeyShareMaterial must bind accepted public randomness and public-key share set root",
        ));
    }
    let (bindings, material_roots) =
        if material_encoding == PUBLIC_KEY_SHARE_MATERIAL_EMBEDDED_ENCODING {
            verify_embedded_public_key_share_material_set(
                material_set,
                setup_context,
                common_binding,
                ring_degree,
                share_records,
            )?
        } else {
            verify_transport_public_key_share_material_set(
                material_set,
                setup_context,
                common_binding,
                ring_degree,
                share_records,
                request,
            )?
        };
    if material_set.get("publicKeyShareMaterialRoots") != Some(&Value::Array(material_roots)) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "publicKeyShareMaterial.publicKeyShareMaterialRoots must match the ordered material records",
        ));
    }
    let material_set_root = value_string(material_set, "publicKeyShareMaterialSetRoot")?;
    validate_hash_string(
        material_set_root,
        "publicKeyShareMaterial.publicKeyShareMaterialSetRoot",
    )?;
    let mut root_input = material_set.clone();
    root_input
        .as_object_mut()
        .expect("public-key share material set object was checked")
        .remove("publicKeyShareMaterialSetRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareRoot", &root_input)?;
    if material_set_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterialSetRoot does not match the canonical public-key share material set",
        ));
    }

    Ok(bindings)
}

fn verify_public_key_share_material_record(
    material_record: &Value,
    setup_context: &Value,
    common_binding: &PublicKeyCommonBinding,
    ring_degree: usize,
    share_records: &BTreeMap<u64, Value>,
) -> CanonicalResult<PublicKeyShareMaterialBinding> {
    if !material_record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share material records must be objects",
        ));
    }
    if let Some(unexpected_field) =
        unexpected_public_key_share_material_record_field(material_record)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("public-key share material contains unexpected field {unexpected_field}"),
        ));
    }
    if material_record.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share material objectType must be PublicKeyShareMaterial",
        ));
    }
    if material_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share material objectVersion must be 1",
        ));
    }
    verify_same_secret_context(material_record, setup_context)?;
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", "public-key-share"),
        (
            "materialEncoding",
            "embedded-full-public-key-share-coefficients",
        ),
        ("proofModelStatus", PUBLIC_KEY_SHARE_SUCCINCT_PROOF_MODEL_STATUS),
    ] {
        if material_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("public-key share material {field_name} must be {expected_value}"),
            ));
        }
    }
    if material_record.get("ringDegree").and_then(Value::as_u64) != Some(ring_degree as u64)
        || material_record.get("rnsLimbCount").and_then(Value::as_u64)
            != Some(DATA_PRIMES.len() as u64)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public-key share material ring degree and limb count must match the material set",
        ));
    }
    if material_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(common_binding.public_matrix_seed_hash.as_str())
        || material_record
            .get("publicKeyCrpRoot")
            .and_then(Value::as_str)
            != Some(common_binding.public_key_crp_root.as_str())
        || material_record
            .get("publicAPolynomialRoot")
            .and_then(Value::as_str)
            != Some(common_binding.public_a_polynomial_root.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public-key share material must bind accepted public randomness",
        ));
    }
    let trustee_roster_position = value_u64(material_record, "trusteeRosterPosition")?;
    let trustee_identity = value_string(material_record, "trusteeIdentity")?.to_string();
    let share_record = share_records.get(&trustee_roster_position).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "public-key share material must reference an accepted share record",
        )
    })?;
    if share_record.get("trusteeIdentity").and_then(Value::as_str)
        != Some(trustee_identity.as_str())
        || material_record
            .get("publicKeyShareRoot")
            .and_then(Value::as_str)
            != share_record
                .get("publicKeyShareRoot")
                .and_then(Value::as_str)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "public-key share material trustee and share root must match the accepted share record",
        ));
    }
    let limbs = material_record
        .get("shareCoefficientVectorsByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "public-key share material coefficients are required",
            )
        })?;
    if limbs.len() != DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material must contain one coefficient vector per Q_share limb",
        ));
    }
    let share_hashes = share_record
        .get("shareCoefficientVectorHash512ByLimb")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "accepted public-key share hashes are required",
            )
        })?;
    let mut coefficients_by_limb = Vec::with_capacity(DATA_PRIMES.len());
    for (rns_limb_index, limb) in limbs.iter().enumerate() {
        if limb.get("rnsLimbIndex").and_then(Value::as_u64) != Some(rns_limb_index as u64)
            || limb.get("rnsPrime").and_then(Value::as_u64) != Some(DATA_PRIMES[rns_limb_index])
            || limb.get("component").and_then(Value::as_str) != Some("b_i")
            || limb.get("coefficientByteLength").and_then(Value::as_u64)
                != Some((ring_degree * 8) as u64)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public-key share material limb metadata must follow Q_share order",
            ));
        }
        let coefficients = coefficient_vector_from_le_hex(
            value_string(limb, "coefficientsLeHex")?,
            ring_degree,
            "public-key share coefficient vector width does not match the material ring degree",
        )?;
        if coefficients
            .iter()
            .any(|coefficient| *coefficient >= DATA_PRIMES[rns_limb_index])
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public-key share coefficient vector contains a non-canonical residue",
            ));
        }
        let coefficient_hash = public_key_share_coefficient_vector_hash(&coefficients);
        if limb.get("coefficientVectorHash512").and_then(Value::as_str)
            != Some(coefficient_hash.as_str())
            || share_hashes
                .get(rns_limb_index)
                .and_then(|share_hash| share_hash.get("coefficientVectorHash512"))
                .and_then(Value::as_str)
                != Some(coefficient_hash.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "public-key share material coefficient hash must match the accepted share record",
            ));
        }
        coefficients_by_limb.push(coefficients);
    }
    let public_key_share_material_root =
        value_string(material_record, "publicKeyShareMaterialRoot")?.to_string();
    validate_hash_string(
        &public_key_share_material_root,
        "publicKeyShareMaterial.shareMaterialRecords.publicKeyShareMaterialRoot",
    )?;
    let mut root_input = material_record.clone();
    root_input
        .as_object_mut()
        .expect("public-key share material record object was checked")
        .remove("publicKeyShareMaterialRoot");
    let expected_root = derive_protocol_hash("PublicKeyShareRoot", &root_input)?;
    if public_key_share_material_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterialRoot does not match the canonical public-key share material",
        ));
    }

    Ok(PublicKeyShareMaterialBinding {
        trustee_identity,
        trustee_roster_position,
        public_key_share_root: value_string(material_record, "publicKeyShareRoot")?.to_string(),
        public_key_share_material_root,
        coefficients_by_limb,
    })
}

fn unexpected_public_key_share_material_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofModelStatus",
            "materialEncoding",
            "binaryFormat",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "ringDegree",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "publicKeyShareSetRoot",
            "publicKeyShareMaterialRoots",
            "shareMaterialRecords",
            "transport",
            "publicKeyShareMaterialSetRoot",
        ],
    )
}

fn unexpected_public_key_share_material_record_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofModelStatus",
            "materialEncoding",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "rnsLimbCount",
            "ringDegree",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "publicKeyShareRoot",
            "shareCoefficientVectorsByLimb",
            "publicKeyShareMaterialRoot",
        ],
    )
}

fn unexpected_collective_public_key_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "aggregationStatus",
            "materialEncoding",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "ringDegree",
            "publicMatrixSeedHash",
            "publicKeyCrpRoot",
            "publicAPolynomialRoot",
            "sameSecretConsistencyRoot",
            "sameSecretProofSetRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareSetRoot",
            "publicKeyShareProofSetRoot",
            "publicKeyShareMaterialSetRoot",
            "publicKeyShareLnpProofSetRoot",
            "sourceShareMaterialRoots",
            "aggregateCoefficientVectorsByLimb",
            "collectivePublicKeyRoot",
        ],
    )
}
