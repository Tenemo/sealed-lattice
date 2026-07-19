import {
    canonicalStreamKernelContext,
    registerCanonicalStreamKernelContext,
} from '../canonical-stream-runtime.js';

import { registerActionRandomnessKernelContext } from './action-randomness-kernel-context.js';
import { registerCommonProofKernelContext } from './common-proof-kernel-context.js';
import type { TranscriptCoreKernelContextOwner } from './kernel-contracts.js';
import type { TranscriptCoreKernelCommandRuntime } from './kernel-runtime.js';
import { resolveOptionalNumberExport } from './kernel-runtime.js';
import { registerKernelContexts } from './register-kernel-contexts.js';

export const registerPrivateKernelContexts = (
    kernel: TranscriptCoreKernelContextOwner,
    runtime: TranscriptCoreKernelCommandRuntime,
): void => {
    registerKernelContexts(kernel, runtime);
    registerCommonProofKernelContext(kernel, runtime);

    const actionRandomnessCommand = resolveOptionalNumberExport(
        runtime.wasmExports,
        'sealed_lattice_action_randomness_command',
    );
    if (actionRandomnessCommand !== undefined) {
        registerActionRandomnessKernelContext(kernel, {
            allocate: runtime.allocate,
            command: actionRandomnessCommand,
            deallocate: runtime.deallocate,
            memory: runtime.memory,
            runExclusive: runtime.runExclusive,
        });
    }

    const canonicalStreamContext = canonicalStreamKernelContext(kernel);
    if (canonicalStreamContext === undefined) {
        return;
    }
    const { wasmExports } = runtime;
    registerCanonicalStreamKernelContext(kernel, {
        ...canonicalStreamContext,
        aggregateThresholdShareBeginRecipientAuthority:
            resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_aggregate_threshold_share_begin_recipient_authority',
            ),
        aggregateThresholdShareAbsorbAuthenticatedRecipientPayload:
            resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_aggregate_threshold_share_absorb_authenticated_recipient_payload',
            ),
        aggregateThresholdShareDiscardRecipientAuthority:
            resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_aggregate_threshold_share_discard_recipient_authority',
            ),
        mailboxGcmAuthenticateChunk: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_mailbox_gcm_authenticate_chunk',
        ),
        mailboxGcmBeginEncryptor: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_mailbox_gcm_begin_encryptor',
        ),
        mailboxGcmBeginVerifier: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_mailbox_gcm_begin_verifier',
        ),
        mailboxGcmCancel: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_mailbox_gcm_cancel',
        ),
        mailboxGcmDecryptChunk: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_mailbox_gcm_decrypt_chunk',
        ),
        mailboxGcmEncryptChunk: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_mailbox_gcm_encrypt_chunk',
        ),
        mailboxGcmFinishAuthentication: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_mailbox_gcm_finish_authentication',
        ),
        mailboxGcmFinishDecryptor: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_mailbox_gcm_finish_decryptor',
        ),
        mailboxGcmFinishEncryptor: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_mailbox_gcm_finish_encryptor',
        ),
        setupGenerationAuthorityBegin: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_setup_generation_authority_begin',
        ),
        setupGenerationAuthorityRelease: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_setup_generation_authority_release',
        ),
        setupGenerationPublicKeyShareBodyByteLength:
            resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_setup_generation_public_key_share_body_byte_length',
            ),
        setupGenerationPublicKeyShareBodyCancel: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_setup_generation_public_key_share_body_cancel',
        ),
        setupGenerationPublicKeyShareBodyOpen: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_setup_generation_public_key_share_body_open',
        ),
        setupGenerationPublicKeyShareBodyRead: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_setup_generation_public_key_share_body_read',
        ),
        setupGenerationPublicKeyShareSourceByteLength:
            resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_setup_generation_public_key_share_source_byte_length',
            ),
        setupGenerationRecipientVssPayloadByteLength:
            resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_setup_generation_recipient_vss_payload_byte_length',
            ),
        setupGenerationRecipientVssPayloadCancel: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_setup_generation_recipient_vss_payload_cancel',
        ),
        setupGenerationRecipientVssPayloadOpen: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_setup_generation_recipient_vss_payload_open',
        ),
        setupGenerationRecipientVssPayloadRead: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_setup_generation_recipient_vss_payload_read',
        ),
        setupGenerationRecipientVssPayloadSourceByteLength:
            resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_setup_generation_recipient_vss_payload_source_byte_length',
            ),
        setupGenerationRecipientVssPayloadSourceRecipientRosterPosition:
            resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_setup_generation_recipient_vss_payload_source_recipient_roster_position',
            ),
    });
};
