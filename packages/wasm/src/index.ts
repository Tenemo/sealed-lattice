import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
    stageBgvTargetDecryptionAggregateOpeningMaterials,
} from './bgv-canonical-stream-runtime.js';
import { createWasmBrowserActionStorageWorkerKernel } from './local-storage-root-worker-kernel.js';
import {
    canonicalErrorCodes,
    createPublishedSdkKernelLoader,
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
    type FoundationCanonicalTupleValidation,
    type FoundationSchemaObjectValidation,
    type PublishedSdkKernel,
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
    bgvCanonicalStreamFamilies,
    createWasmBrowserActionStorageWorkerKernel,
    createPublishedSdkKernelLoader,
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
    FoundationCanonicalTupleValidation,
    FoundationSchemaObjectValidation,
    PublishedSdkKernel,
    TranscriptCoreKernelLoaderOptions,
    TranscriptCoreKernelSharePoint,
    TranscriptCorePlaintextComparison,
};
export type {
    BgvCanonicalStreamFamily,
    BgvCanonicalStreamRuntime,
    BgvCanonicalStreamVerifierLease,
    BgvTargetDecryptionAggregateOpeningMaterialSource,
} from './bgv-canonical-stream-runtime.js';
export {
    FoundationBoardInternalError,
    FoundationBoardRefusalError,
    foundationBoardCandidateObjectHash,
    openFoundationBoardSession,
} from './foundation-board-session.js';
export type {
    FoundationBoardCandidate,
    FoundationBoardIngestionLimits,
    FoundationBoardSession,
    FoundationBoardSessionInput,
    FoundationBoardSessionState,
} from './foundation-board-session.js';

// This private, never-published workspace loader is dev- and test-only scaffolding: it
// loads the freshly built dist kernel with the explicit unpinned opt-in so committed
// source never has to track a build-derived hash. The published integrity gate lives in
// the SDK instead — packages/sdk/src/kernel.ts pins the normalized WASM hash into its
// built dist/kernel.js, and tools/ci/verify-packed-package.ts enforces it at pack time.
export const loadTranscriptCoreKernel: () => Promise<TranscriptCoreKernel> =
    createTranscriptCoreKernelLoader(transcriptCoreKernelUrl, {
        allowUnpinnedKernel: true,
    });

// A fresh, unmemoized kernel instance with its own WebAssembly linear memory,
// separate from the shared singleton above. Dev/test fixtures use this to run
// heavy proof generation on a throwaway instance so the prover's transient peak
// ratchets that instance's linear memory rather than the singleton's, and is
// reclaimed once the caller drops its reference. Each call builds a new loader
// and invokes it once, so callers must not share the returned kernel across
// fixtures they expect to be independent. Same dev/test-only scope as
// loadTranscriptCoreKernel.
export const loadFreshTranscriptCoreKernel: () => Promise<TranscriptCoreKernel> =
    () =>
        createTranscriptCoreKernelLoader(transcriptCoreKernelUrl, {
            allowUnpinnedKernel: true,
        })();
