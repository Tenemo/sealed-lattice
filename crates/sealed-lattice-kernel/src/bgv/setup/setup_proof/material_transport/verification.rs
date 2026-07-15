use super::*;
use crate::foundation::{FOUNDATION_PROFILE, derive_canonical_stream_descriptor};

fn setup_proof_stream_family(proof_family: &str) -> CanonicalResult<SetupProofFamily> {
    SetupProofFamily::from_wire_label(proof_family)
        .ok_or_else(|| setup_proof_error("setup proof material family has no canonical BGV stream"))
}

pub(crate) fn authenticate_setup_proof_material_stream_for_test(
    proof_family: &str,
    proof_bytes_hash: &str,
    proof_bytes: &[u8],
) -> CanonicalResult<()> {
    authenticate_setup_proof_material_stream_for_test_inner(
        proof_family,
        proof_bytes_hash,
        proof_bytes,
        None,
    )
}

pub(crate) fn authenticate_setup_proof_material_stream_in_session_for_test(
    proof_family: &str,
    proof_bytes_hash: &str,
    proof_bytes: &[u8],
    accepted_setup_session: crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<()> {
    authenticate_setup_proof_material_stream_for_test_inner(
        proof_family,
        proof_bytes_hash,
        proof_bytes,
        Some(accepted_setup_session),
    )
}

fn authenticate_setup_proof_material_stream_for_test_inner(
    proof_family: &str,
    proof_bytes_hash: &str,
    proof_bytes: &[u8],
    accepted_setup_session: Option<crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<()> {
    let proof_family = setup_proof_stream_family(proof_family)?;
    let family_code = proof_family.stream_code();
    let stream_domain = proof_family.stream_domain();
    let descriptor = derive_canonical_stream_descriptor(stream_domain, proof_bytes).map_err(
        |refusal_reason| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("setup proof canonical stream descriptor was refused: {refusal_reason:?}"),
            )
        },
    )?;
    let descriptor_bytes = descriptor.encode().map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("setup proof canonical stream descriptor did not encode: {error}"),
        )
    })?;
    let material_root_bytes = crate::transcript_core::decode_hex(proof_bytes_hash)?;
    let stream = match accepted_setup_session {
        Some(accepted_setup_session) => crate::bgv::setup::begin_accepted_setup_canonical_stream(
            family_code,
            &material_root_bytes,
            &descriptor_bytes,
            accepted_setup_session,
        ),
        None => crate::bgv::setup::begin_bgv_canonical_stream(
            family_code,
            &material_root_bytes,
            &descriptor_bytes,
        ),
    }
    .map_err(|status| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("setup proof canonical stream did not begin: status {status}"),
        )
    })?;
    for (chunk_index, chunk) in proof_bytes
        .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .enumerate()
    {
        crate::bgv::setup::absorb_bgv_canonical_stream_chunk(
            stream.handle,
            u32::try_from(chunk_index).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "setup proof canonical stream chunk index does not fit u32",
                )
            })?,
            chunk,
        )
        .map_err(|status| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("setup proof canonical stream chunk was refused: status {status}"),
            )
        })?;
    }
    crate::bgv::setup::finish_bgv_canonical_stream(stream.handle).map_err(|status| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("setup proof canonical stream did not finish: status {status}"),
        )
    })?;

    Ok(())
}
