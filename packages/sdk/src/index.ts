import { loadTranscriptCoreKernel } from './kernel.js';
import type {
    TranscriptCoreFixture,
    TranscriptCoreVerificationResult,
} from './types.js';

export type {
    CanonicalError,
    CanonicalErrorCode,
    BaseClaimProfile,
    GoldenTranscriptCoreFixture,
    MalformedObjectFixture,
    MheSecurityStage,
    TranscriptCoreFixture,
    TranscriptCoreReplayFixture,
    TranscriptCoreStatusLabel,
    TranscriptCoreVerificationLabel,
    TranscriptCoreVerificationResult,
} from './types.js';

export const verifyTranscriptCoreFixture = async (
    fixture: TranscriptCoreFixture,
): Promise<TranscriptCoreVerificationResult> => {
    const kernel = await loadTranscriptCoreKernel();
    const verification = kernel.verifyFixture(fixture);

    if ('expectedErrorCode' in verification) {
        return {
            caseName: verification.caseName,
            label: 'TranscriptCoreRejected',
            statusLabels: [],
            rejection: {
                code: verification.expectedErrorCode,
            },
        };
    }

    return {
        caseName: verification.caseName,
        label: 'TranscriptCoreVerified',
        objectHash512: verification.objectHash512,
        chunkRoot: verification.chunkRoot,
        statusLabels: verification.statusLabels,
    };
};
