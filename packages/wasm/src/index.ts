import type {
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from '@sealed-lattice/protocol';

import {
    createTranscriptCoreKernelLoader,
    TranscriptCoreKernelCommandError,
    type TranscriptCoreKernel,
} from './transcript-core-bridge.js';

const transcriptCoreKernelUrl = new URL(
    '../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

export { createTranscriptCoreKernelLoader, TranscriptCoreKernelCommandError };
export type { TranscriptCoreKernel };

export const loadTranscriptCoreKernel: () => Promise<TranscriptCoreKernel> =
    createTranscriptCoreKernelLoader(transcriptCoreKernelUrl);

export const verifyTranscriptCoreFixture = async (
    fixture: TranscriptCoreFixture,
): Promise<TranscriptCoreFixtureVerification> => {
    const kernel = await loadTranscriptCoreKernel();

    return kernel.verifyFixture(fixture);
};

export const roundTripBytesThroughKernel = async (
    input: Uint8Array,
): Promise<Uint8Array> => {
    const kernel = await loadTranscriptCoreKernel();

    return kernel.roundTripBytes(input);
};
