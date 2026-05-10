import type {
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from '@sealed-lattice/types';

type TranscriptCoreKernel = {
    verifyFixture(
        fixture: TranscriptCoreFixture,
    ): TranscriptCoreFixtureVerification;
};

export declare const createTranscriptCoreKernelLoader: (
    transcriptCoreKernelUrl: URL,
) => () => Promise<TranscriptCoreKernel>;
