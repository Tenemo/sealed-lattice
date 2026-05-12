import type {
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from '@sealed-lattice/types';
import { createTranscriptCoreKernelLoader } from '@sealed-lattice/wasm';

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
