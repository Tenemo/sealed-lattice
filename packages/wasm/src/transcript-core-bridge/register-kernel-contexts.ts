import { registerAcceptedSetupSessionKernelContext } from '../accepted-setup-session-runtime.js';
import { registerCanonicalStreamKernelContext } from '../canonical-stream-runtime.js';

import type {
    BgvCollectiveSetupVerification,
    TranscriptCoreKernelContextOwner,
} from './kernel-contracts.js';
import type { TranscriptCoreKernelCommandRuntime } from './kernel-runtime.js';
import {
    resolveNumberExport,
    resolveOptionalNumberExport,
    runKernelCommand,
    TranscriptCoreKernelCommandError,
} from './kernel-runtime.js';

const translateAcceptedSetupCommandFailure = <Result>(
    operation: () => Result,
): Result => {
    try {
        return operation();
    } catch (error) {
        if (
            error instanceof TranscriptCoreKernelCommandError &&
            error.code === 'InvalidFixture'
        ) {
            throw new TranscriptCoreKernelCommandError({
                code: 'InvalidProtocolObject',
                message: error.message.replace(/^InvalidFixture: /u, ''),
            });
        }
        throw error;
    }
};

export const registerKernelContexts = (
    kernel: TranscriptCoreKernelContextOwner,
    runtime: TranscriptCoreKernelCommandRuntime,
): void => {
    const { wasmExports } = runtime;
    const acceptedSetupSessionBegin = resolveNumberExport(
        wasmExports,
        'sealed_lattice_accepted_setup_session_begin',
    );
    const acceptedSetupSessionCancel = resolveNumberExport(
        wasmExports,
        'sealed_lattice_accepted_setup_session_cancel',
    );
    const acceptedSetupCanonicalStreamBegin = resolveNumberExport(
        wasmExports,
        'sealed_lattice_accepted_setup_canonical_stream_begin',
    );
    const acceptedSetupCommandWithLength = resolveNumberExport(
        wasmExports,
        'sealed_lattice_accepted_setup_command_with_length',
    );
    const canonicalStreamAbsorbChunk = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_canonical_stream_absorb_chunk',
    );
    const canonicalStreamBeginVerifier = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_canonical_stream_begin_verifier',
    );
    const canonicalStreamBeginWriter = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_canonical_stream_begin_writer',
    );
    const canonicalStreamCancel = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_canonical_stream_cancel',
    );
    const canonicalStreamFinishVerifier = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_canonical_stream_finish_verifier',
    );
    const canonicalStreamFinishWriter = resolveOptionalNumberExport(
        wasmExports,
        'sealed_lattice_canonical_stream_finish_writer',
    );
    if (
        canonicalStreamAbsorbChunk !== undefined &&
        canonicalStreamBeginVerifier !== undefined &&
        canonicalStreamBeginWriter !== undefined &&
        canonicalStreamCancel !== undefined &&
        canonicalStreamFinishVerifier !== undefined &&
        canonicalStreamFinishWriter !== undefined
    ) {
        registerCanonicalStreamKernelContext(kernel, {
            absorbChunk: canonicalStreamAbsorbChunk,
            allocate: runtime.allocate,
            bgvAbsorbChunk: resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_bgv_canonical_stream_absorb_chunk',
            ),
            bgvBegin: resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_bgv_canonical_stream_begin',
            ),
            bgvCancel: resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_bgv_canonical_stream_cancel',
            ),
            bgvFinish: resolveOptionalNumberExport(
                wasmExports,
                'sealed_lattice_bgv_canonical_stream_finish',
            ),
            beginVerifier: canonicalStreamBeginVerifier,
            beginWriter: canonicalStreamBeginWriter,
            cancel: canonicalStreamCancel,
            deallocate: runtime.deallocate,
            finishVerifier: canonicalStreamFinishVerifier,
            finishWriter: canonicalStreamFinishWriter,
            memory: runtime.memory,
            runExclusive: runtime.runExclusive,
        });
    }

    registerAcceptedSetupSessionKernelContext(kernel, {
        allocate: runtime.allocate,
        begin: acceptedSetupSessionBegin,
        beginCanonicalStream: acceptedSetupCanonicalStreamBegin,
        cancel: acceptedSetupSessionCancel,
        deallocate: runtime.deallocate,
        executeCommand: (request, sessionHandle, beforeKernelInvocation) =>
            translateAcceptedSetupCommandFailure(() =>
                runtime.runExclusive('accepted-setup command', () =>
                    runKernelCommand<BgvCollectiveSetupVerification>(
                        runtime.memory,
                        runtime.allocate,
                        runtime.deallocate,
                        (pointer, length, outputLengthPointer) => {
                            beforeKernelInvocation();
                            return acceptedSetupCommandWithLength(
                                pointer,
                                length,
                                sessionHandle,
                                outputLengthPointer,
                            );
                        },
                        request,
                    ),
                ),
            ),
        memory: runtime.memory,
        runExclusive: runtime.runExclusive,
    });
};
