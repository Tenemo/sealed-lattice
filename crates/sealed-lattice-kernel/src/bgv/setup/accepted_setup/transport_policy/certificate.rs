use super::binary_material::*;

use super::field_access::*;
use super::request_bindings::*;
use super::*;
use crate::hashing::derive_canonical_object_hash;

pub(in super::super) fn verify_transport_certificate(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(transport_certificate) = setup_package.get("setupTransportCertificate") else {
        return Ok(Some(verification_response(
            Some("setupPackageVerification"),
            vec!["setupTransportCertificate".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    match verify_transport_certificate_body(setup_package, request, transport_certificate)? {
        Ok(()) => {}
        Err(refusal) => {
            return Ok(Some(setup_transport_refusal(
                refusal.reason_code,
                refusal.message,
                refusal
                    .object_path
                    .unwrap_or_else(|| "setupPackage.setupTransportCertificate".to_string()),
            )?));
        }
    }

    Ok(None)
}

fn verify_transport_certificate_body(
    setup_package: &Value,
    request: &Value,
    transport_certificate: &Value,
) -> CanonicalResult<Result<(), Refusal>> {
    macro_rules! transport_try {
        ($expression:expr) => {
            match $expression {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }
    macro_rules! transport_canonical_try {
        ($expression:expr) => {
            match $expression? {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }

    if !transport_certificate.is_object() {
        return Ok(Err(Refusal::new(
            "transportCertificateNotObject",
            "setupTransportCertificate must be a root-bound object",
            "setupPackage.setupTransportCertificate",
        )));
    }
    for (field_name, expected_value, reason_code, message) in [
        (
            "objectType",
            SETUP_TRANSPORT_CERTIFICATE_OBJECT_TYPE,
            "transportCertificateTypeMismatch",
            "setupTransportCertificate.objectType must be SetupTransportCertificate",
        ),
        (
            "largeObjectEncoding",
            "binary",
            "transportEncodingMismatch",
            "setupTransportCertificate.largeObjectEncoding must be binary",
        ),
        (
            "chunking",
            "required",
            "transportChunkingMissing",
            "setupTransportCertificate.chunking must be required",
        ),
        (
            "streamVerificationOrder",
            SETUP_TRANSPORT_STREAM_ORDER,
            "transportStreamOrderMismatch",
            "setupTransportCertificate.streamVerificationOrder must match the setup transport parameters",
        ),
        (
            "resumePolicy",
            SETUP_TRANSPORT_RESUME_POLICY,
            "transportResumePolicyMismatch",
            "setupTransportCertificate.resumePolicy must match the setup transport parameters",
        ),
        (
            "lazyLoadingPolicy",
            SETUP_TRANSPORT_LAZY_LOADING_POLICY,
            "transportLazyLoadingPolicyMismatch",
            "setupTransportCertificate.lazyLoadingPolicy must match the setup transport parameters",
        ),
    ] {
        transport_try!(expect_transport_string(
            transport_certificate,
            field_name,
            expected_value,
            reason_code,
            message,
        ));
    }
    transport_try!(expect_transport_u64(
        transport_certificate,
        "objectVersion",
        1,
        "transportCertificateVersionMismatch",
        "setupTransportCertificate.objectVersion must be 1",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "chunkSizeBytes",
        SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        "transportChunkSizeMismatch",
        "setupTransportCertificate.chunkSizeBytes must match the setup transport parameters",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "storageQuotaBytes",
        SETUP_TRANSPORT_STORAGE_QUOTA_BYTES,
        "transportStorageQuotaMismatch",
        "setupTransportCertificate.storageQuotaBytes must match the setup transport parameters",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "largestSingleBufferBytes",
        SETUP_TRANSPORT_LARGEST_SINGLE_BUFFER_BYTES,
        "transportLargestBufferMismatch",
        "setupTransportCertificate.largestSingleBufferBytes must match the setup transport parameters",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "copyCountLimit",
        SETUP_TRANSPORT_COPY_COUNT_LIMIT,
        "transportCopyCountMismatch",
        "setupTransportCertificate.copyCountLimit must match the setup transport parameters",
    ));

    let setup_parameters_hash_value = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "setupParametersHash",
        "transportSetupParametersHashMissing",
        "setupTransportCertificate.setupParametersHash is required",
    ));
    let roster = super::super::accepted_roster_from_package(setup_package);
    if setup_parameters_hash_value
        != super::super::setup_parameters_hash_for_roster(&roster)?.as_str()
    {
        return Ok(Err(Refusal::new(
            "transportSetupParametersHashMismatch",
            "setupTransportCertificate.setupParametersHash must match the roster-derived setup parameters",
            "setupPackage.setupTransportCertificate.setupParametersHash",
        )));
    }

    let aggregate = transport_canonical_try!(verify_setup_transported_objects(
        setup_package,
        request,
        transport_certificate,
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "totalByteLength",
        aggregate.total_byte_length,
        "transportTotalByteLengthMismatch",
        "setupTransportCertificate.totalByteLength must match the aggregate byte count of transported setup objects",
    ));
    transport_try!(expect_transport_u64(
        transport_certificate,
        "chunkCount",
        aggregate.chunk_count,
        "transportChunkCountMismatch",
        "setupTransportCertificate.chunkCount must match the aggregate transported-object chunk count",
    ));
    let full_object_hash = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "fullObjectHash",
        "transportFullObjectHashMissing",
        "setupTransportCertificate.fullObjectHash is required",
    ));
    if full_object_hash != aggregate.full_object_hash {
        return Ok(Err(Refusal::new(
            "transportFullObjectHashMismatch",
            "setupTransportCertificate.fullObjectHash must match the aggregate transported-object set hash",
            "setupPackage.setupTransportCertificate.fullObjectHash",
        )));
    }
    let chunk_hashes = transport_canonical_try!(transport_chunk_hashes(
        transport_certificate,
        aggregate.chunk_count as usize
    ));
    if chunk_hashes != aggregate.chunk_hashes {
        return Ok(Err(Refusal::new(
            "transportChunkHashesMismatch",
            "setupTransportCertificate.chunkHashes must concatenate the transported-object chunk hashes in order",
            "setupPackage.setupTransportCertificate.chunkHashes",
        )));
    }
    let chunk_root = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "chunkRoot",
        "transportChunkRootMissing",
        "setupTransportCertificate.chunkRoot is required",
    ));
    if chunk_root != aggregate.chunk_root {
        return Ok(Err(Refusal::new(
            "transportChunkRootMismatch",
            "setupTransportCertificate.chunkRoot must match the aggregate transported-object chunk manifest",
            "setupPackage.setupTransportCertificate.chunkRoot",
        )));
    }

    let certificate_hash = transport_canonical_try!(require_transport_hash(
        transport_certificate,
        "setupTransportCertificateHash",
        "transportCertificateHashMissing",
        "setupTransportCertificate.setupTransportCertificateHash is required",
    ));
    let mut certificate_hash_input = transport_certificate.clone();
    certificate_hash_input
        .as_object_mut()
        .expect("transport certificate object was checked")
        .remove("setupTransportCertificateHash");
    let expected_certificate_hash = derive_canonical_object_hash(&certificate_hash_input)?;
    if certificate_hash != expected_certificate_hash {
        return Ok(Err(Refusal::new(
            "transportCertificateHashMismatch",
            "setupTransportCertificateHash does not match the canonical setup transport certificate",
            "setupPackage.setupTransportCertificate.setupTransportCertificateHash",
        )));
    }

    Ok(Ok(()))
}

fn verify_setup_transported_objects(
    setup_package: &Value,
    request: &Value,
    transport_certificate: &Value,
) -> CanonicalResult<Result<SetupTransportAggregate, Refusal>> {
    macro_rules! transport_canonical_try {
        ($expression:expr) => {
            match $expression? {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }

    let transported_object_values = match transport_certificate
        .get("transportedObjects")
        .and_then(Value::as_array)
    {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                "transportedObjectsMissing",
                "setupTransportCertificate.transportedObjects must list the transported setup objects",
                "setupPackage.setupTransportCertificate.transportedObjects",
            )));
        }
    };
    if transported_object_values.is_empty() {
        return Ok(Err(Refusal::new(
            "transportedObjectsEmpty",
            "setupTransportCertificate.transportedObjects must bind at least the full public VSS material object",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }

    let mut transported_objects = Vec::with_capacity(transported_object_values.len());
    let mut seen_object_roots = BTreeSet::new();
    let mut expected_chunk_start_index = 0_u64;
    for (object_index, transported_object_value) in transported_object_values.iter().enumerate() {
        let transported_object = transport_canonical_try!(setup_transported_object_binding(
            transported_object_value,
            object_index,
            expected_chunk_start_index,
            &mut seen_object_roots,
        ));
        expected_chunk_start_index = expected_chunk_start_index
            .checked_add(transported_object.chunk_count)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "setup transport chunk count overflowed",
                )
            })?;
        transported_objects.push(transported_object);
    }
    let total_byte_length =
        transported_objects
            .iter()
            .try_fold(0_u64, |byte_length, transported_object| {
                byte_length
                    .checked_add(transported_object.byte_length)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "setup transport total byte length overflowed",
                        )
                    })
            })?;
    let chunk_count =
        transported_objects
            .iter()
            .try_fold(0_u64, |chunk_count, transported_object| {
                chunk_count
                    .checked_add(transported_object.chunk_count)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "setup transport aggregate chunk count overflowed",
                        )
                    })
            })?;
    let chunk_hashes = transported_objects
        .iter()
        .flat_map(|transported_object| transported_object.chunk_hashes.clone())
        .collect::<Vec<_>>();
    let full_object_hash = setup_transport_full_object_set_hash(
        &transported_objects,
        total_byte_length,
        chunk_count,
        &chunk_hashes,
    )?;
    let chunk_root = setup_transport_chunk_manifest_root(
        SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        chunk_count,
        total_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;

    let vss_material_root = package_nested_hash(
        setup_package,
        "vssCoefficientCommitmentMaterial",
        "vssCoefficientCommitmentMaterialRoot",
    )?;
    // The transported VSS material byte length is a function of the validated
    // roster and the material's ring degree, so the expectation is derived from
    // this package's roster and VSS material ring degree. The verifier already
    // validated participantCount and the roster-derived quorums in verify_context
    // before any transport check runs, and the material ring degree is bound by
    // the VSS material set the commitment-material root above recomputes.
    let transport_roster = super::super::accepted_roster_from_package(setup_package);
    let vss_material_ring_degree = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .and_then(|material_set| material_set.get("ringDegree"))
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial.ringDegree was required before setup transport verification",
            )
        })?;
    let expected_vss_material_byte_length = setup_transport_vss_material_byte_length_for_roster(
        &transport_roster,
        vss_material_ring_degree,
    )?;
    let expected_vss_chunk_count = setup_transport_chunk_count(expected_vss_material_byte_length)?;
    let Some(vss_object) = transported_objects.iter().find(|transported_object| {
        transported_object.object_name == SETUP_TRANSPORTED_VSS_MATERIAL_NAME
            && transported_object.object_role == SETUP_TRANSPORTED_VSS_MATERIAL_ROLE
            && transported_object.object_root == vss_material_root
    }) else {
        return Ok(Err(Refusal::new(
            "transportedVssObjectMissing",
            "setupTransportCertificate.transportedObjects must bind vssCoefficientCommitmentMaterial",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    };
    if vss_object.byte_length != expected_vss_material_byte_length
        || vss_object.chunk_count != expected_vss_chunk_count
    {
        return Ok(Err(Refusal::new(
            "transportedVssObjectMetadataMismatch",
            "vssCoefficientCommitmentMaterial transported object metadata must match the accepted setup parameters",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }
    transport_canonical_try!(verify_binary_vss_material_transport_reference(
        setup_package,
        vss_object.byte_length,
        vss_object.chunk_count,
        &vss_object.chunk_root,
        &vss_object.full_object_hash,
    ));
    let mut expected_transported_object_roots = BTreeSet::new();
    expected_transported_object_roots.insert(vss_material_root);
    transport_canonical_try!(verify_setup_transport_request_bindings(
        setup_package,
        request,
        &transported_objects,
        &mut expected_transported_object_roots,
    ));
    transport_canonical_try!(refuse_unexpected_setup_transported_objects(
        &transported_objects,
        &expected_transported_object_roots,
    ));

    Ok(Ok(SetupTransportAggregate {
        total_byte_length,
        chunk_count,
        chunk_hashes,
        chunk_root,
        full_object_hash,
    }))
}

#[derive(Clone, Debug)]
pub(super) struct SetupTransportedObjectBinding {
    pub(super) object_name: String,
    pub(super) object_role: String,
    pub(super) object_root: String,
    pub(super) byte_length: u64,
    pub(super) chunk_start_index: u64,
    pub(super) chunk_count: u64,
    pub(super) chunk_root: String,
    pub(super) chunk_hashes: Vec<String>,
    pub(super) full_object_hash: String,
}

#[derive(Debug)]
struct SetupTransportAggregate {
    total_byte_length: u64,
    chunk_count: u64,
    chunk_hashes: Vec<String>,
    chunk_root: String,
    full_object_hash: String,
}

fn setup_transported_object_binding(
    transported_object: &Value,
    object_index: usize,
    expected_chunk_start_index: u64,
    seen_object_roots: &mut BTreeSet<String>,
) -> CanonicalResult<Result<SetupTransportedObjectBinding, Refusal>> {
    macro_rules! transport_try {
        ($expression:expr) => {
            match $expression {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }
    macro_rules! transport_canonical_try {
        ($expression:expr) => {
            match $expression? {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
    }

    if !transported_object.is_object() {
        return Ok(Err(Refusal::new(
            "transportedObjectNotObject",
            "setupTransportCertificate.transportedObjects entries must be root-bound objects",
            format!("setupPackage.setupTransportCertificate.transportedObjects[{object_index}]"),
        )));
    }
    let object_path =
        format!("setupPackage.setupTransportCertificate.transportedObjects[{object_index}]");
    transport_try!(expect_transport_string_at(
        transported_object,
        "objectType",
        SETUP_TRANSPORTED_OBJECT_TYPE,
        "transportedObjectTypeMismatch",
        "transported object objectType must be SetupTransportedObject",
        &object_path,
    ));
    transport_try!(expect_transport_u64_at(
        transported_object,
        "objectVersion",
        1,
        "transportedObjectVersionMismatch",
        "transported object objectVersion must be 1",
        &object_path,
    ));
    transport_try!(expect_transport_string_at(
        transported_object,
        "encoding",
        "binary",
        "transportedObjectEncodingMismatch",
        "transported object encoding must be binary",
        &object_path,
    ));
    transport_try!(expect_transport_string_at(
        transported_object,
        "loadingPolicy",
        SETUP_TRANSPORTED_OBJECT_LOADING_POLICY,
        "transportedObjectLoadingPolicyMismatch",
        "transported object loading policy must match the setup transport parameters",
        &object_path,
    ));
    let object_name = transport_try!(require_transport_non_empty_string_at(
        transported_object,
        "objectName",
        "transportedObjectNameMissing",
        "transported object objectName is required",
        &object_path,
    ));
    let object_role = transport_try!(require_transport_non_empty_string_at(
        transported_object,
        "objectRole",
        "transportedObjectRoleMissing",
        "transported object objectRole is required",
        &object_path,
    ));
    let object_root = transport_try!(require_transport_hash_at(
        transported_object,
        "objectRoot",
        "transportedObjectRootMissing",
        "transported object objectRoot is required",
        &object_path,
    ));
    if !seen_object_roots.insert(object_root.clone()) {
        return Ok(Err(Refusal::new(
            "transportedObjectRootDuplicate",
            "setupTransportCertificate.transportedObjects must not contain duplicate objectRoot entries",
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }
    let byte_length = transport_try!(require_positive_transport_u64_at(
        transported_object,
        "byteLength",
        "transportedObjectByteLengthInvalid",
        "transported object byteLength must be positive",
        &object_path,
    ));
    // Threading chunkStartIndex enforces a gap-free, non-overlapping, ordered global chunk stream, so transported objects cannot overlap, reorder, or leave holes while still matching the aggregate chunk count.
    let chunk_start_index = transport_try!(require_transport_u64_at(
        transported_object,
        "chunkStartIndex",
        "transportedObjectStartIndexMissing",
        "transported object chunkStartIndex is required",
        &object_path,
    ));
    if chunk_start_index != expected_chunk_start_index {
        return Ok(Err(Refusal::new(
            "transportedObjectStartIndexMismatch",
            "transported object chunkStartIndex must continue the aggregate transport stream",
            format!("{object_path}.chunkStartIndex"),
        )));
    }
    let chunk_count = transport_try!(require_positive_transport_u64_at(
        transported_object,
        "chunkCount",
        "transportedObjectChunkCountInvalid",
        "transported object chunkCount must be positive",
        &object_path,
    ));
    let expected_chunk_count = setup_transport_chunk_count(byte_length)?;
    if chunk_count != expected_chunk_count {
        return Ok(Err(Refusal::new(
            "transportedObjectChunkCountMismatch",
            "transported object chunkCount must match byteLength and the setup transport chunk size",
            format!("{object_path}.chunkCount"),
        )));
    }
    let full_object_hash = transport_try!(require_transport_hash_at(
        transported_object,
        "fullObjectHash",
        "transportedObjectFullHashMissing",
        "transported object fullObjectHash is required",
        &object_path,
    ));
    let chunk_hashes = transport_canonical_try!(transport_hashes_at(
        transported_object,
        "chunkHashes",
        usize::try_from(chunk_count).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "transported object chunkCount does not fit usize",
            )
        })?,
        &object_path,
    ));
    let chunk_root = transport_try!(require_transport_hash_at(
        transported_object,
        "chunkRoot",
        "transportedObjectChunkRootMissing",
        "transported object chunkRoot is required",
        &object_path,
    ));

    Ok(Ok(SetupTransportedObjectBinding {
        object_name,
        object_role,
        object_root,
        byte_length,
        chunk_start_index,
        chunk_count,
        chunk_root,
        chunk_hashes,
        full_object_hash,
    }))
}

pub(super) struct SetupTransportExpectedObject {
    pub(super) object_name: &'static str,
    pub(super) object_role: &'static str,
    pub(super) object_root: String,
    pub(super) byte_length: u64,
    pub(super) chunk_root: String,
    pub(super) chunk_hashes: Vec<String>,
    pub(super) full_object_hash: String,
    pub(super) object_path: String,
}

#[derive(Clone, Copy)]
pub(super) struct SetupTransportHashFieldNames {
    pub(super) byte_length: &'static str,
    pub(super) full_object_hash: &'static str,
    pub(super) chunk_root: &'static str,
    pub(super) chunk_hashes: &'static str,
}

#[derive(Clone, Copy)]
pub(super) struct SetupTransportMaterialDescriptor {
    pub(super) object_name: &'static str,
    pub(super) object_role: &'static str,
    pub(super) object_root: &'static str,
    pub(super) hash_fields: SetupTransportHashFieldNames,
}

pub(super) const SETUP_TRANSPORT_DIRECT_HASH_FIELDS: SetupTransportHashFieldNames =
    SetupTransportHashFieldNames {
        byte_length: "totalByteLength",
        full_object_hash: "fullObjectHash",
        chunk_root: "chunkRoot",
        chunk_hashes: "chunkHashes",
    };

pub(super) const SETUP_TRANSPORT_PLAIN_PROOF_HASH_FIELDS: SetupTransportHashFieldNames =
    SETUP_TRANSPORT_DIRECT_HASH_FIELDS;

pub(super) const SETUP_TRANSPORT_PROOF_PREFIXED_HASH_FIELDS: SetupTransportHashFieldNames =
    SetupTransportHashFieldNames {
        byte_length: "proofTotalByteLength",
        full_object_hash: "proofFullObjectHash",
        chunk_root: "proofChunkRoot",
        chunk_hashes: "proofChunkHashes",
    };

fn refuse_unexpected_setup_transported_objects(
    transported_objects: &[SetupTransportedObjectBinding],
    expected_object_roots: &BTreeSet<String>,
) -> CanonicalResult<Result<(), Refusal>> {
    for transported_object in transported_objects {
        if expected_object_roots.contains(&transported_object.object_root) {
            continue;
        }

        return Ok(Err(Refusal::new(
            "transportedObjectUnexpected",
            format!(
                "setupTransportCertificate.transportedObjects contains unrequested transported object {} with role {}",
                transported_object.object_name, transported_object.object_role
            ),
            "setupPackage.setupTransportCertificate.transportedObjects",
        )));
    }

    Ok(Ok(()))
}
