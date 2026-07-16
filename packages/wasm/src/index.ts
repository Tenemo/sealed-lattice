import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
} from './bgv-canonical-stream-runtime.js';
import {
    foundationObjectTypes,
    openCanonicalBoardVerifierSession,
} from './canonical-board-runtime.js';
import {
    describeClosedWorkerCommonProofGenerationFamilyAdapter,
    describeClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
} from './common-proof-worker-runtime.js';
import { openFinalityVerifierSession } from './finality-verifier-runtime.js';
import { openFoundationCeremonyRuntime } from './foundation-ceremony-runtime.js';
import {
    certifyClosedWorkerActionRandomnessReservation,
    createWasmBrowserActionStorageWorkerKernel,
    openClosedWorkerCommonProofScratchStorage,
    openClosedWorkerSetupMailboxRandomness,
    openClosedWorkerStructuredCommitmentOpenings,
    prepareClosedWorkerVerifiedCommonProofApplication,
    openClosedWorkerVerifiedStateDurableBinding,
    produceClosedWorkerActionRandomnessReservationIntent,
    produceClosedWorkerActionRandomnessReservationWitnessVote,
    verifyClosedWorkerActionRandomnessReservationIntentForWitness,
    type ClosedWorkerPreparedCommonProofApplication,
    type ClosedWorkerCommonProofScratchRecordIdentifierInput,
    type ClosedWorkerCommonProofScratchStorage,
    type ClosedWorkerStructuredCommitmentOpeningCapability,
    type ClosedWorkerStructuredCommitmentOpeningOperations,
    type ClosedWorkerSetupMailboxRandomnessOperations,
} from './local-storage-root-worker-kernel.js';
import { openMailboxGcmRuntime } from './mailbox-gcm-runtime.js';
import {
    createTranscriptCoreKernelLoader,
    TranscriptCoreKernelCommandError,
    type AcceptedSetupSession,
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
    certifyClosedWorkerActionRandomnessReservation,
    createWasmBrowserActionStorageWorkerKernel,
    createTranscriptCoreKernelLoader,
    describeClosedWorkerCommonProofGenerationFamilyAdapter,
    describeClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter,
    foundationObjectTypes,
    openBgvCanonicalStreamRuntime,
    openCanonicalBoardVerifierSession,
    openClosedWorkerSetupMailboxRandomness,
    openClosedWorkerCommonProofScratchStorage,
    openClosedWorkerStructuredCommitmentOpenings,
    prepareClosedWorkerVerifiedCommonProofApplication,
    openClosedWorkerVerifiedStateDurableBinding,
    produceClosedWorkerActionRandomnessReservationIntent,
    produceClosedWorkerActionRandomnessReservationWitnessVote,
    runClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
    verifyClosedWorkerActionRandomnessReservationIntentForWitness,
    openFinalityVerifierSession,
    openFoundationCeremonyRuntime,
    openMailboxGcmRuntime,
    TranscriptCoreKernelCommandError,
};
export type {
    CanonicalFoundationActionDefinition,
    CanonicalFoundationBoardPolicy,
    CanonicalFoundationManifest,
    FoundationCeremonyRuntime,
    FoundationManifestInput,
} from './foundation-ceremony-runtime.js';
export type {
    AcceptedSetupSession,
    ClosedWorkerSetupMailboxRandomnessOperations,
    ClosedWorkerCommonProofScratchRecordIdentifierInput,
    ClosedWorkerCommonProofScratchStorage,
    ClosedWorkerPreparedCommonProofApplication,
    ClosedWorkerStructuredCommitmentOpeningCapability,
    ClosedWorkerStructuredCommitmentOpeningOperations,
    TranscriptCoreKernel,
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
export type {
    AuthenticatedCommonProofInputStore,
    ClosedWorkerCommonProofGenerationFamilyAdapter,
    ClosedWorkerCommonProofGenerationFamilyAdapterDescription,
    ClosedWorkerCommonProofVerificationFamilyAdapter,
    ClosedWorkerCommonProofVerificationFamilyAdapterDescription,
    CommonProofCanonicalOutputStore,
    CommonProofExternalMemoryOperation,
    CommonProofExternalMemoryReadResult,
    CommonProofExternalMemoryRequest,
    CommonProofExternalMemoryTransactionExecutor,
    CommonProofGenerationCheckpoint,
    CommonProofGenerationWorkerOptions,
    CommonProofApplicationFreshnessCoordinate,
    CommonProofVerificationWorkerOptions,
    VerifiedCommonProofCapability,
} from './common-proof-worker-runtime.js';
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
    CanonicalBoardContextInput,
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
    copyRuntimeBuildAuthorityBindingDescription,
    createBrowserRuntimeBuildFetcher,
    openBrowserRuntimeBuildCache,
    RuntimeBuildPreflightError,
} from './runtime-build-preflight.js';
export type {
    RuntimeBuildActivation,
    RuntimeBuildAuthorityBinding,
    RuntimeBuildAuthorityBindingDescription,
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
