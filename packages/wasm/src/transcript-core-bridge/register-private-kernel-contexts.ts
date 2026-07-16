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
        bgvMaterialReaderBegin: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_bgv_canonical_material_reader_begin',
        ),
        bgvMaterialReaderCancel: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_bgv_canonical_material_reader_cancel',
        ),
        bgvMaterialReaderFinish: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_bgv_canonical_material_reader_finish',
        ),
        bgvMaterialReaderReadChunk: resolveOptionalNumberExport(
            wasmExports,
            'sealed_lattice_bgv_canonical_material_reader_read_chunk',
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
    });
};
