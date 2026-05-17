import type {
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from '@sealed-lattice/types';

import {
    canonicalErrorCodes,
    createTranscriptCoreKernelLoader,
    TranscriptCoreKernelCommandError,
    type BallotPrivacyEncodedRelationVectorVerification,
    type BallotPrivacyKernelVerification,
    type BallotPrivacyLinearProofVectorVerification,
    type BallotPrivacyProofBackendStatus,
    type BallotPrivacyReceiverKeyVectorVerification,
    type TranscriptCoreKernelSharePoint,
    type TranscriptCorePlaintextComparison,
    type TranscriptCoreKernel,
} from './transcript-core-bridge.js';

const transcriptCoreKernelUrl = new URL(
    '../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

export {
    canonicalErrorCodes,
    createTranscriptCoreKernelLoader,
    TranscriptCoreKernelCommandError,
};
export type {
    TranscriptCoreKernel,
    BallotPrivacyEncodedRelationVectorVerification,
    BallotPrivacyKernelVerification,
    BallotPrivacyLinearProofVectorVerification,
    BallotPrivacyProofBackendStatus,
    BallotPrivacyReceiverKeyVectorVerification,
    TranscriptCoreKernelSharePoint,
    TranscriptCorePlaintextComparison,
};

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
