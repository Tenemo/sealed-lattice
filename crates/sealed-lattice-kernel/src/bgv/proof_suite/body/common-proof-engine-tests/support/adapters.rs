use super::generation::capture_first_generation_checkpoint;
use super::*;

#[test]
fn wasm_family_adapters_derive_bindings_and_discard_unstarted_preparations_once() {
    let (prepared_generation, _) = prepared_generation_worker_fixture();
    let expected_runtime_binding_hash = prepared_generation.runtime_binding_hash();
    let expected_generation_authorization_hash =
        prepared_generation.generation_authorization_hash();
    let expected_lineage_identifier = prepared_generation.proof_attempt_lineage_identifier();
    let generation_adapter =
        super::super::runtime_ffi::CommonProofGenerationFamilyAdapter::fresh(prepared_generation);
    let generation_adapter_handle =
        super::super::runtime_ffi::retain_common_proof_generation_family_adapter(
            generation_adapter,
        )
        .expect("the exact-family prover adapter is retained");
    let mut described_runtime_binding_hash = [0_u8; 64];
    let mut described_generation_authorization_hash = [0_u8; 64];
    let mut described_lineage_identifier = [0_u8; 32];
    let mut status = u32::MAX;
    assert_eq!(
        unsafe {
            super::super::runtime_ffi::sealed_lattice_common_proof_describe_generation_family_adapter(
                generation_adapter_handle,
                described_runtime_binding_hash.as_mut_ptr(),
                described_generation_authorization_hash.as_mut_ptr(),
                described_lineage_identifier.as_mut_ptr(),
                &mut status,
            )
        },
        0,
    );
    assert_eq!(status, 0);
    assert_eq!(
        described_runtime_binding_hash,
        expected_runtime_binding_hash
    );
    assert_eq!(
        described_generation_authorization_hash,
        expected_generation_authorization_hash
    );
    assert_eq!(described_lineage_identifier, expected_lineage_identifier);
    let generation_handle = unsafe {
        super::super::runtime_ffi::sealed_lattice_common_proof_prepare_generation_family_adapter(
            generation_adapter_handle,
            core::ptr::null(),
            0,
            &mut status,
        )
    };
    assert_ne!(generation_handle, 0);
    assert_eq!(status, 0);
    assert_eq!(
        super::super::runtime_ffi::sealed_lattice_common_proof_discard_prepared_generation(
            generation_handle,
        ),
        0,
    );
    assert_eq!(
        super::super::runtime_ffi::sealed_lattice_common_proof_discard_prepared_generation(
            generation_handle,
        ),
        RefusalReason::ConsumedState.canonical_code() as u32,
        "a discarded prover preparation remains permanently stale",
    );

    let prepared_verification = prepared_verification_worker_fixture();
    let expected_verification_binding_hash = prepared_verification.verification_binding_hash();
    let verification_adapter =
        super::super::runtime_ffi::CommonProofVerificationFamilyAdapter::new(prepared_verification);
    let verification_adapter_handle =
        super::super::runtime_ffi::retain_common_proof_verification_family_adapter(
            verification_adapter,
        )
        .expect("the exact-family verifier adapter is retained");
    let mut described_verification_binding_hash = [0_u8; 64];
    assert_eq!(
        unsafe {
            super::super::runtime_ffi::sealed_lattice_common_proof_describe_verification_family_adapter(
                verification_adapter_handle,
                described_verification_binding_hash.as_mut_ptr(),
                &mut status,
            )
        },
        0,
    );
    assert_eq!(status, 0);
    assert_eq!(
        described_verification_binding_hash,
        expected_verification_binding_hash
    );
    let verification_handle = unsafe {
        super::super::runtime_ffi::sealed_lattice_common_proof_prepare_verification_family_adapter(
            verification_adapter_handle,
            &mut status,
        )
    };
    assert_ne!(verification_handle, 0);
    assert_eq!(status, 0);
    assert_eq!(
        super::super::runtime_ffi::sealed_lattice_common_proof_discard_prepared_verification(
            verification_handle,
        ),
        0,
    );
    assert_eq!(
        super::super::runtime_ffi::sealed_lattice_common_proof_discard_prepared_verification(
            verification_handle,
        ),
        RefusalReason::ConsumedState.canonical_code() as u32,
        "a discarded verifier preparation remains permanently stale",
    );
}

#[test]
fn family_terminal_consumer_refuses_before_positive_verification() {
    let mut consumer_called = false;
    let result = super::super::runtime_ffi::consume_verified_common_proof_with_family_terminal(
        &VerifiedCommonProofCapabilityHandle::from_identifier(0),
        |_capability| {
            consumer_called = true;
            Ok(())
        },
    );
    assert_eq!(result, Err(CommonProofRuntimeError::UnknownOrStaleHandle));
    assert!(
        !consumer_called,
        "decoded bytes cannot invoke a family consumer"
    );
}

#[test]
fn resume_family_adapter_authenticates_checkpoint_before_invoking_family_preparation() {
    let refused_callback_count = Rc::new(Cell::new(0_u32));
    let refused_callback_observation = Rc::clone(&refused_callback_count);
    let refused_adapter = super::super::runtime_ffi::CommonProofGenerationFamilyAdapter::resume(
        super::super::runtime_ffi::CommonProofGenerationFamilyAdapterDescription::new(
            [0x11; 64], [0x22; 64], [0x33; 32],
        ),
        [0x44; 32],
        Hash512::from_bytes([0x55; 64]),
        Box::new(move |_continuation| {
            refused_callback_observation.set(refused_callback_observation.get() + 1);
            Err(CommonProofRuntimeError::WrongVerificationBinding.into())
        }),
    );
    let refused_adapter_handle =
        super::super::runtime_ffi::retain_common_proof_generation_family_adapter(refused_adapter)
            .expect("the malformed-checkpoint adapter is retained");
    let malformed_checkpoint_state = [0x91_u8; 7];
    let mut status = u32::MAX;
    let prepared_handle = unsafe {
        super::super::runtime_ffi::sealed_lattice_common_proof_prepare_generation_family_adapter(
            refused_adapter_handle,
            malformed_checkpoint_state.as_ptr(),
            malformed_checkpoint_state.len(),
            &mut status,
        )
    };
    assert_eq!(prepared_handle, 0);
    assert_ne!(status, 0);
    assert_eq!(
        refused_callback_count.get(),
        0,
        "canonical checkpoint decoding precedes exact-family continuation authority"
    );

    let (authenticated_checkpoint_state, _, _, _) = capture_first_generation_checkpoint();
    let (prepared, _) =
        prepared_generation_worker_fixture_for_checkpoint(Some(&authenticated_checkpoint_state), 0)
            .expect("the authenticated checkpoint prepares the exact resumed attempt");
    let expected_runtime_binding_hash = prepared.runtime_binding_hash();
    let expected_generation_authorization_hash = prepared.generation_authorization_hash();
    let expected_lineage_identifier = prepared.proof_attempt_lineage_identifier();
    let checkpoint_lineage_identifier = prepared.checkpoint_lineage_identifier();
    let checkpoint_schedule_digest = prepared.checkpoint_schedule_digest();

    let wrong_binding_callback_count = Rc::new(Cell::new(0_u32));
    let wrong_binding_callback_observation = Rc::clone(&wrong_binding_callback_count);
    let wrong_binding_adapter =
        super::super::runtime_ffi::CommonProofGenerationFamilyAdapter::resume(
            super::super::runtime_ffi::CommonProofGenerationFamilyAdapterDescription::new(
                expected_runtime_binding_hash,
                expected_generation_authorization_hash,
                expected_lineage_identifier,
            ),
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
            Box::new(move |_continuation| {
                wrong_binding_callback_observation
                    .set(wrong_binding_callback_observation.get() + 1);
                Err(CommonProofRuntimeError::WrongVerificationBinding.into())
            }),
        );
    let wrong_binding_adapter_handle =
        super::super::runtime_ffi::retain_common_proof_generation_family_adapter(
            wrong_binding_adapter,
        )
        .expect("the wrong-binding resume adapter is retained");
    let mut wrong_binding_checkpoint_state = authenticated_checkpoint_state.clone();
    wrong_binding_checkpoint_state[12] ^= 1;
    status = u32::MAX;
    let wrong_binding_prepared_handle = unsafe {
        super::super::runtime_ffi::sealed_lattice_common_proof_prepare_generation_family_adapter(
            wrong_binding_adapter_handle,
            wrong_binding_checkpoint_state.as_ptr(),
            wrong_binding_checkpoint_state.len(),
            &mut status,
        )
    };
    assert_eq!(wrong_binding_prepared_handle, 0);
    assert_ne!(status, 0);
    assert_eq!(
        wrong_binding_callback_count.get(),
        0,
        "the authenticated stable-attempt binding is checked before exact-family continuation authority"
    );

    let mut wrong_runtime_binding_hash = expected_runtime_binding_hash;
    wrong_runtime_binding_hash[0] ^= 1;
    let mut wrong_checkpoint_lineage_identifier = checkpoint_lineage_identifier;
    wrong_checkpoint_lineage_identifier[0] ^= 1;
    let mut wrong_checkpoint_schedule_digest_bytes = checkpoint_schedule_digest.into_bytes();
    wrong_checkpoint_schedule_digest_bytes[0] ^= 1;
    let mismatched_adapter_bindings = [
        (
            wrong_runtime_binding_hash,
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
            "runtime description",
        ),
        (
            expected_runtime_binding_hash,
            wrong_checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
            "checkpoint lineage",
        ),
        (
            expected_runtime_binding_hash,
            checkpoint_lineage_identifier,
            Hash512::from_bytes(wrong_checkpoint_schedule_digest_bytes),
            "checkpoint schedule",
        ),
    ];
    for (
        adapter_runtime_binding_hash,
        adapter_checkpoint_lineage_identifier,
        adapter_checkpoint_schedule_digest,
        mismatch_name,
    ) in mismatched_adapter_bindings
    {
        let mismatch_callback_count = Rc::new(Cell::new(0_u32));
        let mismatch_callback_observation = Rc::clone(&mismatch_callback_count);
        let mismatch_adapter =
            super::super::runtime_ffi::CommonProofGenerationFamilyAdapter::resume(
                super::super::runtime_ffi::CommonProofGenerationFamilyAdapterDescription::new(
                    adapter_runtime_binding_hash,
                    expected_generation_authorization_hash,
                    expected_lineage_identifier,
                ),
                adapter_checkpoint_lineage_identifier,
                adapter_checkpoint_schedule_digest,
                Box::new(move |_continuation| {
                    mismatch_callback_observation.set(mismatch_callback_observation.get() + 1);
                    Err(CommonProofRuntimeError::WrongVerificationBinding.into())
                }),
            );
        let mismatch_adapter_handle =
            super::super::runtime_ffi::retain_common_proof_generation_family_adapter(
                mismatch_adapter,
            )
            .expect("mismatched resume adapter retained");
        status = u32::MAX;
        let mismatch_prepared_handle = unsafe {
            super::super::runtime_ffi::sealed_lattice_common_proof_prepare_generation_family_adapter(
                mismatch_adapter_handle,
                authenticated_checkpoint_state.as_ptr(),
                authenticated_checkpoint_state.len(),
                &mut status,
            )
        };
        assert_eq!(
            mismatch_prepared_handle, 0,
            "wrong {mismatch_name} must be refused"
        );
        assert_ne!(status, 0, "wrong {mismatch_name} returns a refusal");
        assert_eq!(
            mismatch_callback_count.get(),
            0,
            "wrong {mismatch_name} is rejected before exact-family continuation authority"
        );
    }

    let callback_count = Rc::new(Cell::new(0_u32));
    let callback_observation = Rc::clone(&callback_count);
    let adapter = super::super::runtime_ffi::CommonProofGenerationFamilyAdapter::resume(
        super::super::runtime_ffi::CommonProofGenerationFamilyAdapterDescription::new(
            expected_runtime_binding_hash,
            expected_generation_authorization_hash,
            expected_lineage_identifier,
        ),
        checkpoint_lineage_identifier,
        checkpoint_schedule_digest,
        Box::new(move |continuation| {
            assert_eq!(
                continuation.checkpoint_lineage_identifier(),
                checkpoint_lineage_identifier
            );
            assert_eq!(
                continuation.checkpoint_schedule_digest(),
                checkpoint_schedule_digest
            );
            assert!(continuation.next_event_index() > 0);
            callback_observation.set(callback_observation.get() + 1);
            Ok(prepared)
        }),
    );
    let adapter_handle =
        super::super::runtime_ffi::retain_common_proof_generation_family_adapter(adapter)
            .expect("the authenticated resume adapter is retained");
    let prepared_handle = unsafe {
        super::super::runtime_ffi::sealed_lattice_common_proof_prepare_generation_family_adapter(
            adapter_handle,
            authenticated_checkpoint_state.as_ptr(),
            authenticated_checkpoint_state.len(),
            &mut status,
        )
    };
    assert_ne!(prepared_handle, 0);
    assert_eq!(status, 0);
    assert_eq!(callback_count.get(), 1);
    assert_eq!(
        super::super::runtime_ffi::sealed_lattice_common_proof_discard_prepared_generation(
            prepared_handle,
        ),
        0
    );
}
