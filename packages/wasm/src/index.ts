import {
    beginAcceptedSetupEvaluatorSourceCatalog,
    beginAcceptedSetupVerification,
} from './accepted-setup-assembly-runtime.js';
import {
    verifyAcceptedSetupPublicKeyShareInClosedWorker,
    verifyAcceptedSetupSameSecretInClosedWorker,
} from './accepted-setup-proof-verification-runtime.js';
import {
    resolveAggregateThresholdShareAuthenticatedRecipientConsumer,
    type AggregateThresholdShareAuthenticatedRecipientConsumer,
    type AggregateThresholdShareRecipientAuthority,
    type AggregateThresholdShareRecipientAuthorityInput,
    type ClosedWorkerAggregateThresholdShareRecipientAuthorityInput,
} from './aggregate-threshold-share-authenticated-recipient.js';
import { openVerifiedBallotAggregationInClosedWorker } from './ballot-aggregation-runtime.js';
import {
    generateBallotValidityInClosedWorker,
    verifyBallotValidityInClosedWorker,
} from './ballot-validity-runtime.js';
import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
} from './bgv-canonical-stream-runtime.js';
import {
    foundationObjectTypes,
    openCanonicalBoardVerifierSession,
} from './canonical-board-runtime.js';
import {
    CommonProofWorkerRuntimeError,
    describeClosedWorkerCommonProofGenerationFamilyAdapter,
    describeClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
} from './common-proof-worker-runtime.js';
import { prepareEvaluatorReplayInClosedWorker } from './evaluator-replay-runtime.js';
import {
    openFinalityVerifierSession,
    releaseVerifiedEvaluatorReplay,
} from './finality-verifier-runtime.js';
import { openFoundationCeremonyRuntime } from './foundation-ceremony-runtime.js';
import {
    certifyClosedWorkerActionRandomnessReservation,
    createWasmBrowserActionStorageWorkerKernel,
    openClosedWorkerAggregateThresholdShareRecipientAuthority,
    openClosedWorkerCommonProofScratchStorage,
    openClosedWorkerSetupMailboxRandomness,
    prepareClosedWorkerVerifiedCommonProofApplication,
    openClosedWorkerVerifiedStateDurableBinding,
    produceClosedWorkerActionRandomnessReservationIntent,
    produceClosedWorkerActionRandomnessReservationWitnessVote,
    verifyClosedWorkerActionRandomnessReservationIntentForWitness,
    type ClosedWorkerPreparedCommonProofApplication,
    type ClosedWorkerCommonProofScratchRecordIdentifierInput,
    type ClosedWorkerCommonProofScratchStorage,
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
import { generateVssShareLinkageInClosedWorker } from './vss-share-linkage-generation-runtime.js';
import {
    verifyVssShareLinkageInClosedWorker,
    type VerifiedVssShareLinkageTerminal,
} from './vss-share-linkage-verification-runtime.js';

const transcriptCoreKernelUrl = new URL(
    '../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

export {
    beginAcceptedSetupEvaluatorSourceCatalog,
    beginAcceptedSetupVerification,
    bgvCanonicalStreamFamilies,
    certifyClosedWorkerActionRandomnessReservation,
    CommonProofWorkerRuntimeError,
    createWasmBrowserActionStorageWorkerKernel,
    createTranscriptCoreKernelLoader,
    describeClosedWorkerCommonProofGenerationFamilyAdapter,
    describeClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter,
    foundationObjectTypes,
    generateBallotValidityInClosedWorker,
    generateVssShareLinkageInClosedWorker,
    openBgvCanonicalStreamRuntime,
    openCanonicalBoardVerifierSession,
    openClosedWorkerAggregateThresholdShareRecipientAuthority,
    openClosedWorkerSetupMailboxRandomness,
    openClosedWorkerCommonProofScratchStorage,
    openVerifiedBallotAggregationInClosedWorker,
    prepareClosedWorkerVerifiedCommonProofApplication,
    prepareEvaluatorReplayInClosedWorker,
    openClosedWorkerVerifiedStateDurableBinding,
    produceClosedWorkerActionRandomnessReservationIntent,
    produceClosedWorkerActionRandomnessReservationWitnessVote,
    runClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseVerifiedEvaluatorReplay,
    verifyClosedWorkerActionRandomnessReservationIntentForWitness,
    openFinalityVerifierSession,
    openFoundationCeremonyRuntime,
    openMailboxGcmRuntime,
    resolveAggregateThresholdShareAuthenticatedRecipientConsumer,
    TranscriptCoreKernelCommandError,
    verifyAcceptedSetupPublicKeyShareInClosedWorker,
    verifyAcceptedSetupSameSecretInClosedWorker,
    verifyBallotValidityInClosedWorker,
    verifyVssShareLinkageInClosedWorker,
};
export type {
    AcceptedSetupEvaluatorSourceCatalogSession,
    AcceptedSetupVerificationSession,
} from './accepted-setup-assembly-runtime.js';
export type { AcceptedSetupProofVerificationInput } from './accepted-setup-proof-verification-runtime.js';
export type { VerifiedAcceptedSetupAuthority } from './accepted-setup-verification-runtime.js';
export type {
    VerifiedBallotAggregationSession,
    VerifiedEvaluatorAggregateAuthority,
} from './ballot-aggregation-runtime.js';
export type {
    BallotValidityGenerationMode,
    GeneratedBallotValidityTransport,
    VerifiedBallotOutput,
} from './ballot-validity-runtime.js';
export type {
    EvaluatorKeyStoreRangeReadObservation,
    EvaluatorKeyStoreRangeSource,
    EvaluatorReplayWorkerOptions,
    PreparedEvaluatorReplay,
} from './evaluator-replay-runtime.js';
export type {
    CanonicalFoundationActionDefinition,
    CanonicalFoundationBoardPolicy,
    CanonicalFoundationManifest,
    FoundationCeremonyRuntime,
    FoundationManifestInput,
} from './foundation-ceremony-runtime.js';
export type {
    AcceptedSetupSession,
    AggregateThresholdShareAuthenticatedRecipientConsumer,
    AggregateThresholdShareRecipientAuthority,
    AggregateThresholdShareRecipientAuthorityInput,
    ClosedWorkerSetupMailboxRandomnessOperations,
    ClosedWorkerCommonProofScratchRecordIdentifierInput,
    ClosedWorkerCommonProofScratchStorage,
    ClosedWorkerAggregateThresholdShareRecipientAuthorityInput,
    ClosedWorkerPreparedCommonProofApplication,
    TranscriptCoreKernel,
    DecodedPrivateRandomCursor,
    EncodedPrivateRandomCursor,
    PrivateRandomCursor,
    SetupMailboxSlot,
    TranscriptCoreKernelLoaderOptions,
    VerifiedVssShareLinkageTerminal,
};
export type {
    VerifiedVssShareLinkageBoardCatalog,
    VssShareLinkageGenerationMode,
} from './vss-share-linkage-generation-runtime.js';
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
    AuthenticatedMailboxPlaintextCapability,
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
