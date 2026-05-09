import { createTranscriptCoreKernelLoader } from './internal/transcript-core-bridge.js';
import type {
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from './types.js';

type TranscriptCoreKernel = {
    verifyFixture(
        fixture: TranscriptCoreFixture,
    ): TranscriptCoreFixtureVerification;
};

const transcriptCoreKernelUrl = new URL(
    './sealed-lattice-kernel.wasm',
    import.meta.url,
);

export const loadTranscriptCoreKernel: () => Promise<TranscriptCoreKernel> =
    createTranscriptCoreKernelLoader(transcriptCoreKernelUrl);
