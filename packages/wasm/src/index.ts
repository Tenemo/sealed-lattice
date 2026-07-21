import {
    beginAcceptedSetupEvaluatorSourceCatalog,
    bindAcceptedSetupEvaluatorGeneratedProofsToPackage,
} from './accepted-setup-assembly-runtime.js';
import {
    generateGaloisKeyShareBatchInClosedWorker,
    verifyGaloisKeyShareBatchInClosedWorker,
} from './accepted-setup-galois-key-share-runtime.js';
import {
    generateAcceptedSetupPublicKeyShareInClosedWorker,
    generateAcceptedSetupSameSecretInClosedWorker,
    verifyGeneratedAcceptedSetupPublicKeyShareInClosedWorker,
    verifyGeneratedAcceptedSetupSameSecretInClosedWorker,
} from './accepted-setup-key-relation-generation-runtime.js';
import { beginAcceptedSetupPackageBuilder } from './accepted-setup-package-builder-runtime.js';
import {
    verifyAcceptedSetupPublicKeyShareInClosedWorker,
    verifyAcceptedSetupSameSecretInClosedWorker,
} from './accepted-setup-proof-verification-runtime.js';
import { generateRelinearizationRoundOneAggregateInClosedWorker } from './accepted-setup-relinearization-aggregate-runtime.js';
import {
    activateRelinearizationRoundTwoInClosedWorker,
    generateRelinearizationRoundOneInClosedWorker,
    generateRelinearizationRoundTwoInClosedWorker,
} from './accepted-setup-relinearization-generation-runtime.js';
import {
    verifyAcceptedSetupRelinearizationRoundOneAggregateInClosedWorker,
    verifyAcceptedSetupRelinearizationRoundOneInClosedWorker,
    verifyAcceptedSetupRelinearizationRoundTwoInClosedWorker,
} from './accepted-setup-relinearization-verification-runtime.js';
import {
    resolveAggregateThresholdShareAuthenticatedRecipientConsumer,
    type AggregateThresholdShareAuthenticatedRecipientConsumer,
    type AggregateThresholdShareRecipientAuthority,
    type AggregateThresholdShareRecipientAuthorityInput,
    type ClosedWorkerAggregateThresholdShareRecipientAuthorityInput,
} from './aggregate-threshold-share-authenticated-recipient.js';
import {
    generateAggregateThresholdShareInClosedWorker,
    verifyAggregateThresholdShareInClosedWorker,
} from './aggregate-threshold-share-proof-runtime.js';
import {
    openVerifiedBallotAggregationInClosedWorker,
    resumeVerifiedBallotAggregationFromCheckpointInClosedWorker,
} from './ballot-aggregation-runtime.js';
import {
    generateBallotValidityInClosedWorker,
    verifyBallotValidityInClosedWorker,
} from './ballot-validity-runtime.js';
import {
    foundationObjectTypes,
    openCanonicalBoardVerifierSession,
} from './canonical-board-runtime.js';
import { beginCollectivePublicKeyAggregate } from './collective-public-key-aggregate-runtime.js';
import {
    CommonProofWorkerRuntimeError,
    describeClosedWorkerCommonProofGenerationFamilyAdapter,
    describeClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter,
    runClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
} from './common-proof-worker-runtime.js';
import { constructEvaluatorAggregateInClosedWorker } from './evaluator-aggregate-runtime.js';
import { prepareEvaluatorReplayInClosedWorker } from './evaluator-replay-runtime.js';
import {
    openFinalityVerifierSession,
    releaseVerifiedEvaluatorReplay,
} from './finality-verifier-runtime.js';
import {
    FoundationBootstrapInternalError,
    FoundationBootstrapRefusalError,
    FoundationBootstrapResourceError,
} from './foundation-bootstrap-errors.js';
import { openFoundationCeremonyRuntime } from './foundation-ceremony-runtime.js';
import { encodeCanonicalFoundationRoster } from './foundation-roster-runtime.js';
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
    activateSelectedSuiteRecordSource,
    copySelectedSuiteRecordSourceBytes,
    releaseSelectedSuiteRecordSource,
} from './selected-suite-record-source.js';
import { openBrowserOwnedSetupGenerationAuthorityInClosedWorker } from './setup-generation-recipient-payload.js';
import {
    generateTargetReleaseInClosedWorker,
    reconstructTargetReleaseInClosedWorker,
    verifyTargetReleaseInClosedWorker,
} from './target-release-runtime.js';
import {
    createTranscriptCoreKernelLoader,
    TranscriptCoreKernelCommandError,
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
    beginAcceptedSetupPackageBuilder,
    beginCollectivePublicKeyAggregate,
    bindAcceptedSetupEvaluatorGeneratedProofsToPackage,
    certifyClosedWorkerActionRandomnessReservation,
    CommonProofWorkerRuntimeError,
    createWasmBrowserActionStorageWorkerKernel,
    createTranscriptCoreKernelLoader,
    constructEvaluatorAggregateInClosedWorker,
    describeClosedWorkerCommonProofGenerationFamilyAdapter,
    describeClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofVerificationFamilyAdapter,
    encodeCanonicalFoundationRoster,
    FoundationBootstrapInternalError,
    FoundationBootstrapRefusalError,
    FoundationBootstrapResourceError,
    foundationObjectTypes,
    generateAcceptedSetupPublicKeyShareInClosedWorker,
    generateAcceptedSetupSameSecretInClosedWorker,
    generateAggregateThresholdShareInClosedWorker,
    generateGaloisKeyShareBatchInClosedWorker,
    generateRelinearizationRoundOneAggregateInClosedWorker,
    generateRelinearizationRoundOneInClosedWorker,
    generateRelinearizationRoundTwoInClosedWorker,
    generateBallotValidityInClosedWorker,
    generateTargetReleaseInClosedWorker,
    generateVssShareLinkageInClosedWorker,
    openCanonicalBoardVerifierSession,
    openClosedWorkerAggregateThresholdShareRecipientAuthority,
    openClosedWorkerSetupMailboxRandomness,
    openClosedWorkerCommonProofScratchStorage,
    openVerifiedBallotAggregationInClosedWorker,
    resumeVerifiedBallotAggregationFromCheckpointInClosedWorker,
    prepareClosedWorkerVerifiedCommonProofApplication,
    prepareEvaluatorReplayInClosedWorker,
    openClosedWorkerVerifiedStateDurableBinding,
    produceClosedWorkerActionRandomnessReservationIntent,
    produceClosedWorkerActionRandomnessReservationWitnessVote,
    runClosedWorkerCommonProofGenerationFamilyAdapter,
    runClosedWorkerCommonProofVerificationFamilyAdapter,
    releaseVerifiedEvaluatorReplay,
    reconstructTargetReleaseInClosedWorker,
    verifyClosedWorkerActionRandomnessReservationIntentForWitness,
    openFinalityVerifierSession,
    openFoundationCeremonyRuntime,
    openMailboxGcmRuntime,
    openBrowserOwnedSetupGenerationAuthorityInClosedWorker,
    resolveAggregateThresholdShareAuthenticatedRecipientConsumer,
    activateRelinearizationRoundTwoInClosedWorker,
    activateSelectedSuiteRecordSource,
    copySelectedSuiteRecordSourceBytes,
    releaseSelectedSuiteRecordSource,
    TranscriptCoreKernelCommandError,
    verifyAcceptedSetupPublicKeyShareInClosedWorker,
    verifyAcceptedSetupRelinearizationRoundOneAggregateInClosedWorker,
    verifyAcceptedSetupRelinearizationRoundOneInClosedWorker,
    verifyAcceptedSetupRelinearizationRoundTwoInClosedWorker,
    verifyAcceptedSetupSameSecretInClosedWorker,
    verifyAggregateThresholdShareInClosedWorker,
    verifyGeneratedAcceptedSetupPublicKeyShareInClosedWorker,
    verifyGeneratedAcceptedSetupSameSecretInClosedWorker,
    verifyGaloisKeyShareBatchInClosedWorker,
    verifyBallotValidityInClosedWorker,
    verifyTargetReleaseInClosedWorker,
    verifyVssShareLinkageInClosedWorker,
};
export type {
    AcceptedSetupEvaluatorSourceCatalogSession,
    AcceptedSetupVerificationSession,
} from './accepted-setup-assembly-runtime.js';
export type { AcceptedSetupPackageBuilder } from './accepted-setup-package-builder-runtime.js';
export type { AcceptedSetupProofVerificationInput } from './accepted-setup-proof-verification-runtime.js';
export type {
    AcceptedSetupRelinearizationComponentDescription,
    AcceptedSetupRelinearizationVerificationInput,
} from './accepted-setup-relinearization-verification-runtime.js';
export type {
    GeneratedRelinearizationAggregateProof,
    RelinearizationAggregateComponentDescription,
    RelinearizationAggregateComponentStore,
    RelinearizationAggregateGenerationInput,
    RelinearizationAggregateGenerationMode,
} from './accepted-setup-relinearization-aggregate-runtime.js';
export type {
    GeneratedRelinearizationParticipantProof,
    RelinearizationComponentDescription,
    RelinearizationComponentStore,
    RelinearizationGenerationMode,
    RelinearizationParticipantGenerationInput,
    RelinearizationRoundTwoActivationInput,
} from './accepted-setup-relinearization-generation-runtime.js';
export type {
    AcceptedSetupKeyRelationGenerationInput,
    AcceptedSetupKeyRelationGenerationMode,
    GeneratedAcceptedSetupKeyRelationProof,
    GeneratedAcceptedSetupKeyRelationProofVerificationInput,
} from './accepted-setup-key-relation-generation-runtime.js';
export type { AggregateThresholdShareGenerationMode } from './aggregate-threshold-share-proof-runtime.js';
export type {
    GaloisKeyShareBatchGenerationMode,
    GaloisKeyShareComponentDescription,
    GaloisKeyShareComponentStore,
    GeneratedGaloisKeyShareBatch,
} from './accepted-setup-galois-key-share-runtime.js';
export type { VerifiedAcceptedSetupAuthority } from './accepted-setup-verification-runtime.js';
export type {
    BallotAggregationCheckpointBoundary,
    BallotAggregationCheckpointCustody,
    BallotAggregationCheckpointOperationIdentity,
    BallotAggregationCheckpointReplaySource,
    BallotAggregationSelectionCheckpoint,
    BallotAggregationSelectionIdentity,
    BallotEvaluationWorkerOptions,
    EvaluatorKeyStoreRangeReadObservation,
    EvaluatorKeyStoreRangeSource,
    ExpectedBallotAggregationCheckpointBoundary,
    PreparedVerifiedBallotAggregate,
    ResumedBallotAggregationCheckpoint,
    VerifiedBallotAggregationInput,
    VerifiedBallotAggregationSession,
    VerifiedEvaluatorAggregateAuthority,
} from './ballot-aggregation-runtime.js';
export type {
    BallotValidityGenerationMode,
    GeneratedBallotValidityTransport,
    VerifiedBallotOutput,
} from './ballot-validity-runtime.js';
export type { PreparedEvaluatorReplay } from './evaluator-replay-runtime.js';
export type {
    EvaluatorAggregateConstructionOptions,
    EvaluatorAggregateGenerationMode,
    EvaluatorAggregateSession,
    EvaluatorKeyStoreDescription,
} from './evaluator-aggregate-runtime.js';
export type {
    CollectivePublicKeyAggregate,
    CollectivePublicKeyDescription,
    CollectivePublicKeyGenerationMode,
    CollectivePublicKeyParticipantSource,
} from './collective-public-key-aggregate-runtime.js';
export type {
    CanonicalFoundationActionDefinition,
    CanonicalFoundationBoardPolicy,
    CanonicalFoundationManifest,
    FoundationCeremonyRuntime,
    FoundationManifestInput,
} from './foundation-ceremony-runtime.js';
export type { FoundationRosterEntryInput } from './foundation-roster-runtime.js';
export type { SelectedSuiteRecordSource } from './selected-suite-record-source.js';
export type {
    BrowserOwnedSetupGenerationAuthority,
    BrowserOwnedSetupGenerationAuthorityInput,
    SetupGenerationPublicKeyShareBodySource,
    SetupGenerationRecipientPayloadSource,
} from './setup-generation-recipient-payload.js';
export type {
    GeneratedTargetReleaseTransport,
    ReconstructedTargetRelease,
    TargetReleaseGenerationMode,
    TargetReleasePartialOutputStoreResolver,
    TargetReleasePartialRole,
    VerifiedTargetReleaseShare,
} from './target-release-runtime.js';
export type {
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
