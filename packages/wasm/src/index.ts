import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
    stageBgvTargetDecryptionAggregateOpeningMaterials,
} from './bgv-canonical-stream-runtime.js';
import { createWasmBrowserActionStorageWorkerKernel } from './local-storage-root-worker-kernel.js';
import { openMailboxGcmRuntime } from './mailbox-gcm-runtime.js';
import {
    createTranscriptCoreKernelLoader,
    TranscriptCoreKernelCommandError,
    type ActionRandomnessDerivationInput,
    type ActionContextInput,
    type AcceptedSetupSession,
    type BgvCollectiveSetupParametersDescription,
    type BgvCollectiveSetupVerification,
    type BgvLocalTrusteeSetupStateVerification,
    type BgvPrivateVssShareEnvelopeVerification,
    type BgvRnsParametersDescription,
    type CanonicalFoundationValueValidation,
    type CanonicalFoundationValueValidationInput,
    type CeremonyContextInput,
    type DecodedActionRandomnessDerivationInput,
    type DecodedPrivateRandomBlockInput,
    type DecodedPrivateRandomCursor,
    type EncodedActionRandomnessDerivationInput,
    type EncodedPrivateRandomBlockInput,
    type EncodedPrivateRandomCursor,
    type GeneratedProofSuiteCandidate,
    type PrivateRandomCursor,
    type PrivateRandomBlockInput,
    type SetupMailboxSlot,
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
    openMailboxGcmRuntime,
    stageBgvTargetDecryptionAggregateOpeningMaterials,
    TranscriptCoreKernelCommandError,
};
export type {
    ActionContextInput,
    ActionRandomnessDerivationInput,
    AcceptedSetupSession,
    TranscriptCoreKernel,
    BgvCollectiveSetupParametersDescription,
    BgvCollectiveSetupVerification,
    BgvLocalTrusteeSetupStateVerification,
    BgvPrivateVssShareEnvelopeVerification,
    BgvRnsParametersDescription,
    CanonicalFoundationValueValidation,
    CanonicalFoundationValueValidationInput,
    CeremonyContextInput,
    DecodedActionRandomnessDerivationInput,
    DecodedPrivateRandomBlockInput,
    DecodedPrivateRandomCursor,
    EncodedActionRandomnessDerivationInput,
    EncodedPrivateRandomBlockInput,
    EncodedPrivateRandomCursor,
    GeneratedProofSuiteCandidate,
    PrivateRandomCursor,
    PrivateRandomBlockInput,
    SetupMailboxSlot,
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
    canonicalStreamDomains,
    openCanonicalStreamWorkerRuntime,
} from './canonical-stream-runtime.js';
export type {
    MailboxGcmEncryptorLease,
    MailboxGcmLeaseState,
    MailboxGcmRuntime,
    MailboxGcmVerifierLease,
} from './mailbox-gcm-runtime.js';
export type {
    CanonicalStreamChunkPull,
    CanonicalStreamChunkSink,
    CanonicalStreamDomain,
    CanonicalStreamRuntimeCounterSnapshot,
    CanonicalStreamVerifierLease,
    CanonicalStreamWorkerRuntime,
    CanonicalStreamWriterLease,
} from './canonical-stream-runtime.js';
export {
    copyVerifiedStateDurableBinding,
    openStateVerifierSession,
    stateCapabilityKinds,
    stateIntentKinds,
    stateWitnessVoteKinds,
} from './state-verifier-runtime.js';
export type {
    StateDurableBindingDescription,
    StateIntentKind,
    PreparedStateWitnessVote,
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
    StateWitnessVoteKind,
    UntrustedStateWitnessVoteCarrier,
    VerifiedStateDurableBinding,
    VerifiedStateIntent,
    VerifiedStateOutput,
    VerifiedStateOutputIntent,
    VerifiedStateRecovery,
    VerifiedStateRecoveryIntent,
    VerifiedStateReservation,
    VerifiedStateReservationIntent,
} from './state-verifier-runtime.js';
export {
    compileRuntimeBuildBootstrap,
    createBrowserRuntimeBuildFetcher,
    openBrowserRuntimeBuildCache,
    RuntimeBuildPreflightError,
} from './runtime-build-preflight.js';
export type {
    RuntimeBuildActivation,
    RuntimeBuildBootstrapPin,
    RuntimeBuildByteSource,
    RuntimeBuildCache,
    RuntimeBuildFetcher,
    RuntimeBuildFetchResponse,
    RuntimeBuildPreflightEnvironment,
    RuntimeBuildWorkerPreflight,
} from './runtime-build-preflight.js';
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
