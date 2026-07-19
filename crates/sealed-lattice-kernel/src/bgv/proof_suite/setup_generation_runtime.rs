//! Browser/WASM runtime boundary for complete setup-generation population.
//!
//! The caller supplies only live process-local handles owned by the selected
//! suite, canonical-board, action-randomness, and state-verifier runtimes.
//! Public-randomness facts and all private setup material are derived inside
//! Rust; no witness value, root, trace row, or generated coefficient crosses
//! into this factory from JavaScript.

use crate::{
    bgv::setup::{
        SetupGenerationAuthorityHandle, SetupGenerationPublicKeyShareSourceHandle,
        SetupGenerationRecipientPayloadSourceHandle, cancel_setup_generation_public_key_share_body,
        cancel_setup_generation_recipient_vss_payload, open_setup_generation_public_key_share_body,
        open_setup_generation_recipient_vss_payload,
        populate_browser_owned_setup_generation_authority,
        read_setup_generation_public_key_share_body,
        read_setup_generation_recipient_vss_payload_chunk, release_setup_generation_authority,
        setup_generation_public_key_share_body_byte_length,
        setup_generation_public_key_share_source_byte_length,
        setup_generation_recipient_vss_payload_byte_length,
        setup_generation_recipient_vss_payload_source_byte_length,
        setup_generation_recipient_vss_payload_source_recipient_roster_position,
        verify_public_randomness_board_sources,
    },
    foundation::{
        BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, FOUNDATION_PROFILE, RefusalReason,
        STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, resolve_verified_board_application_sources,
        retain_action_private_randomness_for_exact_family, verified_state_reservation_binding,
    },
};

use super::runtime_ffi::{runtime_error_status, with_common_proof_selected_suite};

const PUBLIC_RANDOMNESS_OBJECT_FAMILY_COUNT: usize = 3;

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

fn expected_public_randomness_object_handle_count() -> Result<usize, u32> {
    usize::from(FOUNDATION_PROFILE.participant_count)
        .checked_mul(PUBLIC_RANDOMNESS_OBJECT_FAMILY_COUNT)
        .ok_or_else(|| refusal_status(RefusalReason::OutsideSupportedProfile))
}

/// Builds one complete setup-generation authority from positive upstream
/// capabilities already retained in this WASM instance.
#[allow(clippy::too_many_arguments)]
pub(crate) fn begin_setup_generation_authority(
    selected_suite_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    ordered_public_randomness_object_handles: &[u32],
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
) -> Result<SetupGenerationAuthorityHandle, u32> {
    if selected_suite_handle == 0
        || board_verifier_session_handle == 0
        || action_randomness_handle == 0
        || state_verifier_session_handle == 0
        || verified_reservation_handle == 0
        || board_verifier_session_capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH
        || state_verifier_session_capability.len() != STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH
        || ordered_public_randomness_object_handles.len()
            != expected_public_randomness_object_handle_count()?
        || ordered_public_randomness_object_handles.contains(&0)
    {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }

    let verified_sources = resolve_verified_board_application_sources(
        board_verifier_session_handle,
        board_verifier_session_capability,
        ordered_public_randomness_object_handles,
    )?;
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let mut source_iterator = verified_sources.into_iter();
    let setup_intent_sources = source_iterator
        .by_ref()
        .take(participant_count)
        .collect::<Vec<_>>();
    let commitment_sources = source_iterator
        .by_ref()
        .take(participant_count)
        .collect::<Vec<_>>();
    let reveal_sources = source_iterator
        .by_ref()
        .take(participant_count)
        .collect::<Vec<_>>();
    if source_iterator.next().is_some() {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let verified_public_randomness = verify_public_randomness_board_sources(
        setup_intent_sources,
        commitment_sources,
        reveal_sources,
    )
    .map_err(refusal_status)?;
    let action_private_randomness =
        retain_action_private_randomness_for_exact_family(action_randomness_handle)?;
    let verified_reservation_binding = verified_state_reservation_binding(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
    )?;

    with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
        populate_browser_owned_setup_generation_authority(
            selected_suite,
            &verified_public_randomness,
            action_private_randomness,
            verified_reservation_binding,
        )
    })
    .map_err(runtime_error_status)?
    .map_err(refusal_status)
}

pub(crate) fn setup_generation_public_key_share_body_byte_length_by_identifier(
    authority_handle: u32,
) -> Result<u64, u32> {
    setup_generation_public_key_share_body_byte_length(
        &SetupGenerationAuthorityHandle::from_identifier(authority_handle),
    )
    .map_err(refusal_status)
}

pub(crate) fn open_setup_generation_public_key_share_body_by_identifier(
    authority_handle: u32,
) -> Result<u32, u32> {
    open_setup_generation_public_key_share_body(&SetupGenerationAuthorityHandle::from_identifier(
        authority_handle,
    ))
    .map(|source_handle| source_handle.identifier())
    .map_err(refusal_status)
}

pub(crate) fn setup_generation_public_key_share_source_byte_length_by_identifier(
    source_handle: u32,
) -> Result<u64, u32> {
    setup_generation_public_key_share_source_byte_length(
        &SetupGenerationPublicKeyShareSourceHandle::from_identifier(source_handle),
    )
    .map_err(refusal_status)
}

pub(crate) fn read_setup_generation_public_key_share_body_by_identifier(
    source_handle: u32,
    expected_offset: u64,
    output: &mut [u8],
) -> Result<(), u32> {
    read_setup_generation_public_key_share_body(
        &SetupGenerationPublicKeyShareSourceHandle::from_identifier(source_handle),
        expected_offset,
        output,
    )
    .map_err(refusal_status)
}

pub(crate) fn cancel_setup_generation_public_key_share_body_by_identifier(
    source_handle: u32,
) -> Result<(), u32> {
    cancel_setup_generation_public_key_share_body(
        SetupGenerationPublicKeyShareSourceHandle::from_identifier(source_handle),
    )
    .map_err(refusal_status)
}

pub(crate) fn setup_generation_recipient_payload_byte_length(
    authority_handle: u32,
    recipient_roster_position: u16,
) -> Result<u64, u32> {
    setup_generation_recipient_vss_payload_byte_length(
        &SetupGenerationAuthorityHandle::from_identifier(authority_handle),
        recipient_roster_position,
    )
    .map_err(refusal_status)
}

pub(crate) fn open_setup_generation_recipient_payload(
    authority_handle: u32,
    recipient_roster_position: u16,
) -> Result<u32, u32> {
    open_setup_generation_recipient_vss_payload(
        &SetupGenerationAuthorityHandle::from_identifier(authority_handle),
        recipient_roster_position,
    )
    .map(|source_handle| source_handle.identifier())
    .map_err(refusal_status)
}

pub(crate) fn setup_generation_recipient_payload_source_byte_length(
    source_handle: u32,
) -> Result<u64, u32> {
    setup_generation_recipient_vss_payload_source_byte_length(
        &SetupGenerationRecipientPayloadSourceHandle::from_identifier(source_handle),
    )
    .map_err(refusal_status)
}

pub(crate) fn setup_generation_recipient_payload_source_recipient_roster_position(
    source_handle: u32,
) -> Result<u16, u32> {
    setup_generation_recipient_vss_payload_source_recipient_roster_position(
        &SetupGenerationRecipientPayloadSourceHandle::from_identifier(source_handle),
    )
    .map_err(refusal_status)
}

pub(crate) fn read_setup_generation_recipient_payload(
    source_handle: u32,
    expected_offset: u64,
    output: &mut [u8],
) -> Result<(), u32> {
    let chunk = read_setup_generation_recipient_vss_payload_chunk(
        &SetupGenerationRecipientPayloadSourceHandle::from_identifier(source_handle),
        expected_offset,
        output.len(),
    )
    .map_err(refusal_status)?;
    if chunk.len() != output.len() {
        let _ = cancel_setup_generation_recipient_payload(source_handle);
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    output.copy_from_slice(&chunk);
    Ok(())
}

pub(crate) fn cancel_setup_generation_recipient_payload(source_handle: u32) -> Result<(), u32> {
    cancel_setup_generation_recipient_vss_payload(
        SetupGenerationRecipientPayloadSourceHandle::from_identifier(source_handle),
    )
    .map_err(refusal_status)
}

pub(crate) fn release_setup_generation_authority_by_identifier(
    authority_handle: u32,
) -> Result<(), u32> {
    release_setup_generation_authority(SetupGenerationAuthorityHandle::from_identifier(
        authority_handle,
    ))
    .map_err(refusal_status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_factory_rejects_wrong_capability_lengths_before_resolving_handles() {
        let expected_handle_count = expected_public_randomness_object_handle_count().unwrap();
        let object_handles = vec![1_u32; expected_handle_count];
        let wrong_type_status = refusal_status(RefusalReason::WrongTypeOrLength);

        assert!(matches!(
            begin_setup_generation_authority(
                1,
                1,
                &[0_u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH - 1],
                &object_handles,
                1,
                1,
                &[0_u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
                1,
            ),
            Err(status) if status == wrong_type_status
        ));
        assert!(matches!(
            begin_setup_generation_authority(
                1,
                1,
                &[0_u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
                &object_handles,
                1,
                1,
                &[0_u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH + 1],
                1,
            ),
            Err(status) if status == wrong_type_status
        ));
    }

    #[test]
    fn authority_factory_rejects_incomplete_or_zero_handle_sets_before_registry_access() {
        let expected_handle_count = expected_public_randomness_object_handle_count().unwrap();
        let wrong_type_status = refusal_status(RefusalReason::WrongTypeOrLength);
        let board_capability = [0_u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH];
        let state_capability = [0_u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH];

        for object_handles in [
            vec![1_u32; expected_handle_count - 1],
            vec![1_u32; expected_handle_count + 1],
            {
                let mut handles = vec![1_u32; expected_handle_count];
                handles[expected_handle_count / 2] = 0;
                handles
            },
        ] {
            assert!(matches!(
                begin_setup_generation_authority(
                    1,
                    1,
                    &board_capability,
                    &object_handles,
                    1,
                    1,
                    &state_capability,
                    1,
                ),
                Err(status) if status == wrong_type_status
            ));
        }
    }
}
