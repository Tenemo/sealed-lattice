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
    type BgvRnsProfileDescription,
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
    '940068ff9b2f7b6f3728953a25163245d801c8fb7e322e51d645c68b51282032';

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
    BgvRnsProfileDescription,
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
