import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
} from './bgv-canonical-stream-runtime.js';
import {
    foundationObjectTypes,
    openCanonicalBoardVerifierSession,
} from './canonical-board-runtime.js';
import { openFinalityVerifierSession } from './finality-verifier-runtime.js';
import {
    createWasmBrowserActionStorageWorkerKernel,
    openClosedWorkerSetupMailboxRandomness,
    openClosedWorkerStructuredCommitmentOpenings,
    type ClosedWorkerStructuredCommitmentOpeningCapability,
    type ClosedWorkerStructuredCommitmentOpeningOperations,
    type ClosedWorkerSetupMailboxRandomnessOperations,
} from './local-storage-root-worker-kernel.js';
import { openMailboxGcmRuntime } from './mailbox-gcm-runtime.js';
import {
    createTranscriptCoreKernelLoader,
    TranscriptCoreKernelCommandError,
    type AcceptedSetupSession,
    type DecodedProofApplicationBinding,
    type DecodedPrivateRandomCursor,
    type EncodedPrivateRandomCursor,
    type PrivateRandomCursor,
    type SetupMailboxSlot,
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
    foundationObjectTypes,
    openBgvCanonicalStreamRuntime,
    openCanonicalBoardVerifierSession,
    openClosedWorkerSetupMailboxRandomness,
    openClosedWorkerStructuredCommitmentOpenings,
    openFinalityVerifierSession,
    openMailboxGcmRuntime,
    TranscriptCoreKernelCommandError,
};
export type {
    AcceptedSetupSession,
    ClosedWorkerSetupMailboxRandomnessOperations,
    ClosedWorkerStructuredCommitmentOpeningCapability,
    ClosedWorkerStructuredCommitmentOpeningOperations,
    TranscriptCoreKernel,
    DecodedProofApplicationBinding,
    DecodedPrivateRandomCursor,
    EncodedPrivateRandomCursor,
    PrivateRandomCursor,
    SetupMailboxSlot,
    TranscriptCoreKernelLoaderOptions,
};
export type {
    BgvCanonicalStreamFamily,
    BgvCanonicalStreamRuntime,
    BgvCanonicalStreamVerifierLease,
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
export type {
    CanonicalBoardVerifierConfiguration,
    CanonicalBoardVerifierSession,
    CanonicalBoardVerifierSessionState,
    FoundationObjectType,
    UntrustedCanonicalBoardCarrier,
    VerifiedTranscriptObject,
    VerifiedTranscriptObjectDescription,
} from './canonical-board-runtime.js';
export {
    copyVerifiedStateDurableBinding,
    openStateVerifierSession,
    stateCapabilityKinds,
    stateWitnessVoteKinds,
} from './state-verifier-runtime.js';
export type {
    FinalityVerification,
    FinalityVerifierConfiguration,
    FinalityVerifierSession,
    VerifiedEvaluatorReplay,
    VerifiedFinality,
    VerifiedFinalityDescription,
} from './finality-verifier-runtime.js';
export {
    copyVerifiedProofApplicationBinding,
    verifyProofApplicationBinding,
} from './proof-application-runtime.js';
export type {
    ProofApplicationAuthorityContext,
    ProofApplicationBindingDescription,
    VerifiedProofApplicationBinding,
} from './proof-application-runtime.js';
export type {
    StateDurableBindingDescription,
    StateOutputIntentVerification,
    StateOutputIntentVerificationLease,
    StateOutputVerification,
    StateOutputVerificationLease,
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
