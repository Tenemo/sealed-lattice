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
    type BallotPrivacyProofGeneration,
    type BallotPrivacyReceiverKeyProofGeneration,
    type BallotPrivacyReceiverKeyProofGenerationPreparation,
    type BallotPrivacyReceiverKeyVectorVerification,
    type AggregateBridgeEncryptionGeneration,
    type AggregateBridgeEncryptionVerification,
    type BgvBaseConversionFixture,
    type BgvBatchPlaintextEncoding,
    type BgvCiphertextConventionFixture,
    type BgvObjectValidation,
    type BgvReferenceOracleRejection,
    type BgvRnsProfileReport,
    type TranscriptCoreKernelLoaderOptions,
    type TranscriptCoreKernelSharePoint,
    type TranscriptCorePlaintextComparison,
    type TranscriptCoreKernel,
} from './transcript-core-bridge.js';

const transcriptCoreKernelUrl = new URL(
    '../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);
const packagedTranscriptCoreKernelNormalizedSha256Hex =
    '788fb82b2fb7b1f07aa3e0a43176f6e4fc9da6a489a0d2c1613987a891a2c167';

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
    BallotPrivacyProofGeneration,
    BallotPrivacyReceiverKeyProofGeneration,
    BallotPrivacyReceiverKeyProofGenerationPreparation,
    BallotPrivacyReceiverKeyVectorVerification,
    AggregateBridgeEncryptionGeneration,
    AggregateBridgeEncryptionVerification,
    BgvBaseConversionFixture,
    BgvBatchPlaintextEncoding,
    BgvCiphertextConventionFixture,
    BgvObjectValidation,
    BgvReferenceOracleRejection,
    BgvRnsProfileReport,
    TranscriptCoreKernelLoaderOptions,
    TranscriptCoreKernelSharePoint,
    TranscriptCorePlaintextComparison,
};

export const loadTranscriptCoreKernel: () => Promise<TranscriptCoreKernel> =
    createTranscriptCoreKernelLoader(transcriptCoreKernelUrl, {
        expectedKernelSha256Hex:
            packagedTranscriptCoreKernelNormalizedSha256Hex,
    });

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
