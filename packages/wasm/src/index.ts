import {
    canonicalErrorCodes,
    createTranscriptCoreKernelLoader,
    TranscriptCoreKernelCommandError,
    type BgvAcceptedSetupHandoff,
    type BgvBaseConversionFixture,
    type BgvBatchPlaintextEncoding,
    type BgvCiphertextConventionFixture,
    type BgvCollectiveSetupProfileDescription,
    type BgvCollectiveSetupVerification,
    type BgvCompactSameSecretBridgeProofStatement,
    type BgvCompactVssSameSecretBridgeProofMaterialSetVerification,
    type BgvCompactVssShareLinkageBinaryProofMaterialTransport,
    type BgvCompactVssShareLinkageBinaryProofMaterialVerification,
    type BgvCompactVssShareLinkageProofMaterialSetVerification,
    type BgvLocalTrusteeSetupStateVerification,
    type BgvObjectValidation,
    type BgvPrivateVssShareEnvelopeVerification,
    type BgvRnsProfileDescription,
    type BgvTargetDecryptionDevelopmentFixture,
    type BgvTargetDecryptionResultVerification,
    type BgvTargetDecryptionShareBinaryProofMaterialTransport,
    type BgvTargetDecryptionShareBinaryProofMaterialVerification,
    type BgvTargetDecryptionShareProofMaterial,
    type BgvTargetDecryptionShareProofMaterialVerification,
    type BgvTargetDecryptionShareProofStatement,
    type BgvThresholdShareCommitmentDerivation,
    type TranscriptCoreKernelLoaderOptions,
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
    BgvAcceptedSetupHandoff,
    TranscriptCoreKernel,
    BgvBaseConversionFixture,
    BgvBatchPlaintextEncoding,
    BgvCiphertextConventionFixture,
    BgvCollectiveSetupProfileDescription,
    BgvCollectiveSetupVerification,
    BgvCompactSameSecretBridgeProofStatement,
    BgvCompactVssSameSecretBridgeProofMaterialSetVerification,
    BgvCompactVssShareLinkageBinaryProofMaterialTransport,
    BgvCompactVssShareLinkageBinaryProofMaterialVerification,
    BgvCompactVssShareLinkageProofMaterialSetVerification,
    BgvLocalTrusteeSetupStateVerification,
    BgvObjectValidation,
    BgvPrivateVssShareEnvelopeVerification,
    BgvRnsProfileDescription,
    BgvTargetDecryptionDevelopmentFixture,
    BgvTargetDecryptionResultVerification,
    BgvTargetDecryptionShareBinaryProofMaterialTransport,
    BgvTargetDecryptionShareBinaryProofMaterialVerification,
    BgvTargetDecryptionShareProofMaterial,
    BgvTargetDecryptionShareProofMaterialVerification,
    BgvTargetDecryptionShareProofStatement,
    BgvThresholdShareCommitmentDerivation,
    TranscriptCoreKernelLoaderOptions,
    TranscriptCoreKernelSharePoint,
    TranscriptCorePlaintextComparison,
};

// This private, never-published workspace loader is dev- and test-only scaffolding: it
// loads the freshly built dist kernel with the explicit unpinned opt-in so committed
// source never has to track a build-derived hash. The published integrity gate lives in
// the SDK instead — packages/sdk/src/kernel.ts pins the normalized WASM hash into its
// built dist/kernel.js, and tools/ci/verify-packed-package.ts enforces it at pack time.
export const loadTranscriptCoreKernel: () => Promise<TranscriptCoreKernel> =
    createTranscriptCoreKernelLoader(transcriptCoreKernelUrl, {
        allowUnpinnedKernel: true,
    });
