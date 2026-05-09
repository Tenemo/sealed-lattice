import type {
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from '../types.js';

type TranscriptCoreKernel = {
    verifyFixture(
        fixture: TranscriptCoreFixture,
    ): TranscriptCoreFixtureVerification;
};

export declare const createTranscriptCoreKernelLoader: (
    transcriptCoreKernelUrl: URL,
) => () => Promise<TranscriptCoreKernel>;
