import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
    stageBgvTargetDecryptionAggregateOpeningMaterials,
} from './bgv-canonical-stream-runtime.js';
import { createWasmBrowserActionStorageWorkerKernel } from './local-storage-root-worker-kernel.js';
import {
    createTranscriptCoreKernelLoader,
    TranscriptCoreKernelCommandError,
    type AcceptedSetupSession,
    type BgvCollectiveSetupParametersDescription,
    type BgvCollectiveSetupVerification,
    type BgvLocalTrusteeSetupStateVerification,
    type BgvPrivateVssShareEnvelopeVerification,
    type BgvRnsParametersDescription,
    type BgvTargetDecryptionReleaseSetupContext,
    type BgvTargetDecryptionResultReleaseShareEvidence,
    type BgvTargetDecryptionResultReleaseCompletion,
    type TranscriptCoreKernelLoaderOptions,
    type TranscriptCoreKernel,
} from './transcript-core-bridge.js';

const transcriptCoreKernelUrl = new URL(
    '../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

export {
    bgvCanonicalStreamFamilies,
    createWasmBrowserActionStorageWorkerKernel,
    createTranscriptCoreKernelLoader,
    openBgvCanonicalStreamRuntime,
    stageBgvTargetDecryptionAggregateOpeningMaterials,
    TranscriptCoreKernelCommandError,
};
export type {
    AcceptedSetupSession,
    TranscriptCoreKernel,
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupVerification,
    BgvLocalTrusteeSetupStateVerification,
    BgvPrivateVssShareEnvelopeVerification,
    BgvRnsParametersDescription,
    BgvTargetDecryptionReleaseSetupContext,
    BgvTargetDecryptionResultReleaseShareEvidence,
    BgvTargetDecryptionResultReleaseCompletion,
    TranscriptCoreKernelLoaderOptions,
};
export type {
    BgvCanonicalStreamFamily,
    BgvCanonicalStreamRuntime,
    BgvCanonicalStreamVerifierLease,
    BgvTargetDecryptionAggregateOpeningMaterialSource,
} from './bgv-canonical-stream-runtime.js';
export {
    openStateVerifierSession,
    stateCapabilityKinds,
    stateIntentKinds,
} from './state-verifier-runtime.js';
export type {
    StateIntentKind,
    StateOutputIntentVerification,
    StateOutputIntentVerificationLease,
    StateOutputVerification,
    StateOutputVerificationLease,
    StateRecoveryIntentVerification,
    StateRecoveryVerification,
    StateReservationIntentVerification,
    StateReservationVerification,
    StateVerifierSession,
    StateVerifierSessionInput,
    VerifiedStateIntent,
    VerifiedStateOutput,
    VerifiedStateOutputIntent,
    VerifiedStateRecovery,
    VerifiedStateRecoveryIntent,
    VerifiedStateReservation,
    VerifiedStateReservationIntent,
} from './state-verifier-runtime.js';
// Workspace builds use an unpinned kernel; the published SDK verifies its normalized hash.
export const loadTranscriptCoreKernel: () => Promise<TranscriptCoreKernel> =
    createTranscriptCoreKernelLoader(transcriptCoreKernelUrl, {
        allowUnpinnedKernel: true,
    });

// Each fresh loader has isolated WebAssembly memory for proof-generation fixtures.
export const loadFreshTranscriptCoreKernel: () => Promise<TranscriptCoreKernel> =
    () =>
        createTranscriptCoreKernelLoader(transcriptCoreKernelUrl, {
            allowUnpinnedKernel: true,
        })();
