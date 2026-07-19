import { registerCanonicalStreamKernelContext } from '../canonical-stream-runtime.js';

import type { TranscriptCoreKernelContextOwner } from './kernel-contracts.js';
import type { TranscriptCoreKernelCommandRuntime } from './kernel-runtime.js';
import { resolveOptionalNumberExport } from './kernel-runtime.js';

export const registerKernelContexts = (
    kernel: TranscriptCoreKernelContextOwner,
    runtime: TranscriptCoreKernelCommandRuntime,
): void => {
    const { wasmExports } = runtime;
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
};
