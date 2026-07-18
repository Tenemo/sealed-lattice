import {
    BrowserActionStorageCustodyError,
    stateCapabilityKinds,
    type BrowserActionProofAttemptBinding,
    type BrowserActionRandomnessReservationCertificationInput,
    type BrowserActionRandomnessReservationIntentProductionInput,
    type BrowserActionRandomnessReservationIntentWitnessVerificationInput,
    type BrowserActionRandomnessReservationVerificationInput,
    type BrowserActionRandomnessReservationWitnessVoteProductionInput,
    type BrowserActionStateReservationVerificationInput,
    type BrowserActionStateVerifierSessionInput,
    type BrowserOpenedActionRandomnessSession,
    type BrowserProducedActionRandomnessReservation,
    type BrowserProducedActionRandomnessReservationIntent,
    type BrowserTargetReleaseAttemptInput,
    type ProtocolHash,
    type VerificationResult,
    type BrowserLocalRecordIdentifierInput,
    type BrowserLocalRecordOpenInput,
    type BrowserLocalRecordSealInput,
    type BrowserActionStorageRootBinding,
    type BrowserActionStorageWorkerKernel,
    type BrowserAuthenticatedRepairProtectionInput,
    type UntrustedExpectedStorageRootCommitment,
    type WorkerPreparedBrowserFoundationInitialization,
    type WorkerDerivedBrowserFoundationInitializationRecords,
    type WorkerPreparedDeviceWrappingState,
    type WorkerOpenedBrowserAuthenticatedRepairProtection,
    type WorkerBrowserFoundationInitializationPreparationInput,
} from '@sealed-lattice/types';

import { actionRandomnessCommandOutputByteLimit } from '../action-randomness-command-byte-limits.js';
import { actionRandomnessCommandIdentifiers } from '../action-randomness-command-identifiers.js';
import {
    beginAggregateThresholdShareRecipientAuthorityFromRetainedActionRandomness,
    type AggregateThresholdShareRecipientAuthority,
    type ClosedWorkerAggregateThresholdShareRecipientAuthorityInput,
} from '../aggregate-threshold-share-authenticated-recipient.js';
import { byteArraysEqual } from '../byte-array.js';
import {
    abortVerifiedCommonProofApplication,
    confirmVerifiedCommonProofApplication,
    prepareVerifiedCommonProofApplication,
    type CommonProofApplicationFreshnessCoordinate,
    type VerifiedCommonProofCapability,
} from '../common-proof-worker-runtime.js';
import {
    constructVerifiedStateWitnessVoteCarrierForWorker,
    openStateVerifierSession,
    produceSetupActionRandomnessReservationIntentFromRetainedKernelHandle,
    resolveVerifiedStateReservationKernelAuthorization,
    type StateVerifierSession,
    type VerifiedStateDurableBinding,
    type VerifiedStateReservation,
} from '../state-verifier-runtime.js';
import { type ActionRandomnessKernelContext } from '../transcript-core-bridge/action-randomness-kernel-context.js';
import { resolveCommonProofKernelContext } from '../transcript-core-bridge/common-proof-kernel-context.js';
import type {
    SetupMailboxSlot,
    TranscriptCoreKernel,
} from '../transcript-core-bridge/kernel-types.js';
import { bytesToHex } from '../transcript-core-bridge/kernel-wasm-hash.js';
import { type LocalStorageRootKernelContext } from '../transcript-core-bridge/local-storage-root-kernel-context.js';

import {
    ClosedWorkerCommonProofScratchRecordIdentifierInput,
    ClosedWorkerCommonProofScratchRecordOpenInput,
    ClosedWorkerCommonProofScratchRecordSealInput,
    ClosedWorkerPreparedCommonProofApplication,
    ClosedWorkerSetupMailboxRandomnessOperations,
    RootLease,
    WorkerActionRandomnessRecordContext,
    WorkerActionRandomnessSessionRecord,
    WorkerAuthenticatedRepairProtectionRecord,
    WorkerSealedActionRandomnessSession,
    WorkerSetupMailboxRandomnessInput,
    WorkerStateObject,
    WorkerStateVerifierSession,
    closedWorkerCommonProofScratchStorage,
} from './authorities.js';
import {
    actionRandomnessRootByteLength,
    actionStorageRootByteLength,
    arrayBufferFromBytes,
    attemptIdentifierByteLength,
    capabilityByteLength,
    concatenateBytes,
    copyBinding,
    copyBoundedBytes,
    copyBrowserFoundationInitializationInput,
    copyExactBytes,
    decodeUnsigned32,
    destroyBrowserFoundationInitializationInput,
    deviceWrappingNonceByteLength,
    deviceWrappingTagByteLength,
    domainSeparatedHash,
    encodeActionRandomnessRecordContext,
    encodeBinding,
    encodeCanonicalUnsigned16,
    encodeCanonicalUnsigned32,
    encodeFoundationWitnessAuthorizedEmpty,
    encodeFoundationWitnessRole,
    encodeLocalRecordExpectedContext,
    encodeLocalRecordIdentifierInput,
    encodeUnsigned32,
    foundationHashByteLength,
    foundationWitnessStateKeyDomain,
    handleByteLength,
    localRecordNonceByteLength,
    maximumCommandByteLength,
    maximumLocalRecordPlaintextByteLength,
    maximumWrappedStorageRootByteLength,
    mlDsa65SignatureByteLength,
    mlDsa65VerificationKeyByteLength,
    mlKem768CiphertextByteLength,
    mlKem768EncapsulationKeyByteLength,
    mlKem768SharedSecretByteLength,
    objectSignatureContext,
    protocolHashBytes,
    repairTextEncoder,
    requireOpaqueWorkerIdentifier,
    setupMailboxSignatureContext,
    storageNamespacePattern,
    untrustedExpectedCommitmentBytes,
    wasm32WordByteLength,
} from './encoding.js';

const localStorageRootCommands = Object.freeze({
    associatedData: 4,
    commit: 8,
    copyForDeviceWrap: 5,
    decodeDeviceEnvelope: 7,
    destroy: 10,
    discard: 9,
    encodeDeviceEnvelope: 6,
    reset: 13,
    deriveRecordIdentifier: 14,
    sealRecord: 15,
    openRecord: 16,
    hashRecordEnvelope: 17,
    deriveRepairIdentity: 18,
    sealRepairHead: 19,
    openRepairHead: 20,
    digestRepairHead: 21,
    deriveCommonProofExternalMemoryRecordIdentifier: 22,
    sealCommonProofExternalMemoryRecord: 23,
    openCommonProofExternalMemoryRecord: 24,
    stageNew: 1,
    stageOpened: 2,
} as const);

const localStorageRootStatuses = Object.freeze({
    capabilityMismatch: 0x0001_0002,
    consumedState: 0x000d,
    malformedEncoding: 0x0001,
    outsideSupportedProfile: 0x0003,
    resourceLimit: 0x0001_0000,
    staleHandle: 0x0001_0001,
    unsupportedVersionOrSuite: 0x0002,
    wrongContext: 0x0004,
    wrongHashOrRoot: 0x0006,
    wrongTypeOrLength: 0x0005,
} as const);

type DecodedDeviceEnvelope = Readonly<{
    canonicalAssociatedData: Uint8Array<ArrayBuffer>;
    ciphertext: Uint8Array<ArrayBuffer>;
    nonce: Uint8Array<ArrayBuffer>;
    tag: Uint8Array<ArrayBuffer>;
}>;

type CommandFailureContext =
    | 'open'
    | 'recordHash'
    | 'recordOpen'
    | 'recordSeal'
    | 'runtime';

export class WasmBrowserActionStorageWorkerKernel implements BrowserActionStorageWorkerKernel {
    readonly #actionRandomnessContext: ActionRandomnessKernelContext;
    readonly #context: LocalStorageRootKernelContext;
    readonly #cryptoProvider: Crypto;
    readonly #kernel: TranscriptCoreKernel;
    #activeLease: RootLease | undefined;
    #actionRandomnessRootMintConsumed = true;
    #actionRandomnessSessionAcquisitionConsumed = true;
    readonly #actionRandomnessSessions = new Map<
        string,
        WorkerActionRandomnessSessionRecord
    >();
    readonly #authenticatedRepairProtectionSessions = new Map<
        string,
        WorkerAuthenticatedRepairProtectionRecord
    >();
    #operationTail: Promise<void> = Promise.resolve();
    #stagedRootAllowsActionRandomnessMint = false;
    readonly #stateObjects = new Map<string, WorkerStateObject>();
    readonly #stateVerifierSessions = new Map<
        string,
        WorkerStateVerifierSession
    >();
    #stagedLease: RootLease | undefined;

    public constructor(input: {
        actionRandomnessContext: ActionRandomnessKernelContext;
        context: LocalStorageRootKernelContext;
        cryptoProvider: Crypto;
        kernel: TranscriptCoreKernel;
    }) {
        this.#actionRandomnessContext = input.actionRandomnessContext;
        this.#context = input.context;
        this.#cryptoProvider = input.cryptoProvider;
        this.#kernel = input.kernel;
        closedWorkerCommonProofScratchStorage.set(this, {
            deriveRecordIdentifier: (operationInput) =>
                this.#deriveCommonProofScratchRecordIdentifier(operationInput),
            openRecord: (operationInput) =>
                this.#openCommonProofScratchRecord(operationInput),
            sealRecord: (operationInput) =>
                this.#sealCommonProofScratchRecord(operationInput),
        });
    }

    public createAndStageDeviceWrappingState(input: {
        binding: BrowserActionStorageRootBinding;
    }): Promise<WorkerPreparedDeviceWrappingState> {
        return this.#enqueue(() => this.#createAndStage(input.binding));
    }

    public stageDeviceWrappingStateOpen(input: {
        binding: BrowserActionStorageRootBinding;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
        state: WorkerPreparedDeviceWrappingState;
    }): Promise<void> {
        return this.#enqueue(() => this.#stageDeviceWrappingOpen(input));
    }

    public commitStagedActionStorageRoot(): Promise<void> {
        return this.#enqueue(() => this.#commitStaged());
    }

    public discardStagedActionStorageRoot(): Promise<void> {
        return this.#enqueue(() => this.#discardStaged());
    }

    public destroyActiveActionStorageRoot(): Promise<void> {
        return this.#enqueue(() => this.#destroyActive());
    }

    public deriveActiveLocalRecordIdentifier(
        input: BrowserLocalRecordIdentifierInput,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => this.#deriveLocalRecordIdentifier(input));
    }

    public sealActiveLocalRecord(
        input: BrowserLocalRecordSealInput,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => this.#sealLocalRecord(input));
    }

    public openActiveLocalRecord(
        input: BrowserLocalRecordOpenInput,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => this.#openLocalRecord(input));
    }

    #deriveCommonProofScratchRecordIdentifier(
        input: ClosedWorkerCommonProofScratchRecordIdentifierInput,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() =>
            this.#deriveLocalRecordIdentifier(
                input,
                localStorageRootCommands.deriveCommonProofExternalMemoryRecordIdentifier,
            ),
        );
    }

    #sealCommonProofScratchRecord(
        input: ClosedWorkerCommonProofScratchRecordSealInput,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() =>
            this.#sealLocalRecord(
                { ...input, recordVersion: 0n as const },
                localStorageRootCommands.sealCommonProofExternalMemoryRecord,
            ),
        );
    }

    #openCommonProofScratchRecord(
        input: ClosedWorkerCommonProofScratchRecordOpenInput,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() =>
            this.#openLocalRecord(
                { ...input, recordVersion: 0n as const },
                localStorageRootCommands.openCommonProofExternalMemoryRecord,
            ),
        );
    }

    public hashActiveLocalRecordEnvelope(
        envelope: Uint8Array,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => this.#hashLocalRecordEnvelope(envelope));
    }

    public openActiveAuthenticatedRepairProtection(
        input: BrowserAuthenticatedRepairProtectionInput,
    ): Promise<WorkerOpenedBrowserAuthenticatedRepairProtection> {
        return this.#enqueue(() =>
            this.#openActiveAuthenticatedRepairProtection(input),
        );
    }

    public sealAuthenticatedRepairHead(input: {
        plaintext: Uint8Array;
        repairProtectionSessionIdentifier: string;
    }): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => this.#sealAuthenticatedRepairHead(input));
    }

    public openAuthenticatedRepairHead(input: {
        canonicalEnvelope: Uint8Array;
        repairProtectionSessionIdentifier: string;
    }): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => this.#openAuthenticatedRepairHead(input));
    }

    public deriveAuthenticatedRepairHeadDigest(input: {
        sealedHeadBytes: Uint8Array;
        repairProtectionSessionIdentifier: string;
    }): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() =>
            this.#deriveAuthenticatedRepairHeadDigest(input),
        );
    }

    public closeAuthenticatedRepairProtection(
        identifier: string,
    ): Promise<void> {
        return this.#enqueue(() =>
            this.#closeAuthenticatedRepairProtection(identifier),
        );
    }

    public prepareBrowserFoundationInitialization(
        input: WorkerBrowserFoundationInitializationPreparationInput,
    ): Promise<WorkerPreparedBrowserFoundationInitialization> {
        return this.#enqueue(() =>
            this.#prepareBrowserFoundationInitialization(input),
        );
    }

    public deriveBrowserFoundationInitializationRecords(
        input: WorkerBrowserFoundationInitializationPreparationInput,
    ): Promise<WorkerDerivedBrowserFoundationInitializationRecords> {
        return this.#enqueue(() =>
            this.#deriveBrowserFoundationInitializationRecords(input),
        );
    }

    public openActionStateVerifierSession(
        input: BrowserActionStateVerifierSessionInput,
    ): Promise<VerificationResult<string>> {
        return this.#enqueue(() => this.#openActionStateVerifierSession(input));
    }

    public verifyActionStateReservation(
        input: BrowserActionStateReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        return this.#enqueue(() => this.#verifyActionStateReservation(input));
    }

    public verifyActionRandomnessReservation(
        input: BrowserActionRandomnessReservationVerificationInput,
    ): Promise<VerificationResult<string>> {
        return this.#enqueue(() =>
            this.#verifyActionRandomnessReservation(input),
        );
    }

    public produceActionRandomnessReservationIntent(
        input: BrowserActionRandomnessReservationIntentProductionInput,
    ): Promise<
        VerificationResult<BrowserProducedActionRandomnessReservationIntent>
    > {
        return this.#enqueue(() =>
            this.#produceActionRandomnessReservationIntent(input),
        );
    }

    public verifyActionRandomnessReservationIntentForWitness(
        input: BrowserActionRandomnessReservationIntentWitnessVerificationInput,
    ): Promise<VerificationResult<string>> {
        return this.#enqueue(() =>
            this.#verifyActionRandomnessReservationIntentForWitness(input),
        );
    }

    public produceActionRandomnessReservationWitnessVote(
        input: BrowserActionRandomnessReservationWitnessVoteProductionInput,
    ): Promise<VerificationResult<Uint8Array>> {
        return this.#enqueue(() =>
            this.#produceActionRandomnessReservationWitnessVote(input),
        );
    }

    public certifyActionRandomnessReservation(
        input: BrowserActionRandomnessReservationCertificationInput,
    ): Promise<VerificationResult<BrowserProducedActionRandomnessReservation>> {
        return this.#enqueue(() =>
            this.#certifyActionRandomnessReservation(input),
        );
    }

    public releaseActionStateObject(identifier: string): Promise<void> {
        return this.#enqueue(() => this.#releaseActionStateObject(identifier));
    }

    public durableBindingForStateObject(
        identifier: string,
    ): Promise<VerificationResult<VerifiedStateDurableBinding>> {
        return this.#enqueue(() =>
            this.#durableBindingForStateObject(identifier),
        );
    }

    public closeActionStateVerifierSession(identifier: string): Promise<void> {
        return this.#enqueue(() =>
            this.#closeActionStateVerifierSession(identifier),
        );
    }

    public runTerminalSetupCheckpointCommand(
        command: number,
        input: Uint8Array,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => {
            if (!(input instanceof Uint8Array)) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Checkpoint command input must be bytes.',
                );
            }
            const activeLease = this.#requireActiveLease();

            return this.#runCommand(
                command,
                this.#leaseCommandInput(activeLease, input),
                'run an authenticated checkpoint command',
                'runtime',
            );
        });
    }

    public sampleTerminalSetupCheckpointEntropy(
        byteLength: number,
        label: string,
    ): Promise<Uint8Array<ArrayBuffer>> {
        return this.#enqueue(() => {
            if (!Number.isSafeInteger(byteLength) || byteLength <= 0) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'Checkpoint entropy byte length must be a positive safe integer.',
                );
            }

            return this.#randomBytes(byteLength, label);
        });
    }

    public createAndSealActionRandomness(
        input: WorkerActionRandomnessRecordContext,
    ): Promise<WorkerSealedActionRandomnessSession> {
        return this.#enqueue(() => this.#createAndSealActionRandomness(input));
    }

    public openSealedActionRandomness(
        input: WorkerActionRandomnessRecordContext &
            Readonly<{
                actionRandomnessCommitment: Uint8Array;
                canonicalEnvelope: Uint8Array;
            }>,
    ): Promise<BrowserOpenedActionRandomnessSession> {
        return this.#enqueue(() => this.#openSealedActionRandomness(input));
    }

    public closeActionRandomness(sessionIdentifier: string): Promise<void> {
        return this.#enqueue(() =>
            this.#closeActionRandomness(sessionIdentifier),
        );
    }

    public openClosedSetupMailboxRandomness(
        input: WorkerSetupMailboxRandomnessInput,
    ): ClosedWorkerSetupMailboxRandomnessOperations {
        return this.#openClosedSetupMailboxRandomness(input);
    }

    public openClosedAggregateThresholdShareRecipientAuthority(
        input: ClosedWorkerAggregateThresholdShareRecipientAuthorityInput,
    ): Promise<AggregateThresholdShareRecipientAuthority> {
        return this.#enqueue(() =>
            beginAggregateThresholdShareRecipientAuthorityFromRetainedActionRandomness(
                {
                    ...input,
                    actionRandomnessHandle:
                        this.#requireActionRandomnessSession(
                            input.actionRandomnessSessionIdentifier,
                        ),
                    kernel: this.#kernel,
                },
            ),
        );
    }

    public prepareClosedCommonProofApplication(
        capability: VerifiedCommonProofCapability,
        predecessor: CommonProofApplicationFreshnessCoordinate,
    ): Promise<ClosedWorkerPreparedCommonProofApplication> {
        return this.#enqueue(() =>
            this.#prepareClosedCommonProofApplication(capability, predecessor),
        );
    }

    public deriveTargetReleaseAttempt(
        input: BrowserTargetReleaseAttemptInput,
    ): Promise<BrowserActionProofAttemptBinding> {
        return this.#enqueue(() => this.#deriveTargetReleaseAttempt(input));
    }

    #prepareClosedCommonProofApplication(
        capability: VerifiedCommonProofCapability,
        predecessor: CommonProofApplicationFreshnessCoordinate,
    ): ClosedWorkerPreparedCommonProofApplication {
        const prepared = prepareVerifiedCommonProofApplication(
            capability,
            this.#commonProofStorageRootAccess(this.#requireActiveLease()),
            predecessor,
        );
        let state: 'pending' | 'settling' | 'settled' = 'pending';
        const requirePending = (): void => {
            if (state !== 'pending') {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'The prepared common-proof application is already settling or consumed.',
                );
            }
            state = 'settling';
        };
        const settle = (): void => {
            state = 'settled';
            prepared.authorizationFrame.fill(0);
            prepared.proofApplicationSlotHash.fill(0);
        };
        const retryableFailure = (error: unknown): never => {
            state = 'pending';
            throw error;
        };
        return Object.freeze({
            abort: (): Promise<void> => {
                requirePending();
                return this.#enqueue(() => {
                    try {
                        abortVerifiedCommonProofApplication(prepared.authority);
                        settle();
                    } catch (error) {
                        retryableFailure(error);
                    }
                });
            },
            authorizationFrame: prepared.authorizationFrame,
            confirm: ({
                authenticatedAuthorizationFrame,
                successor,
            }): Promise<void> => {
                requirePending();
                return this.#enqueue(() => {
                    try {
                        confirmVerifiedCommonProofApplication(
                            prepared.authority,
                            this.#commonProofStorageRootAccess(
                                this.#requireActiveLease(),
                            ),
                            successor,
                            authenticatedAuthorizationFrame,
                        );
                        settle();
                    } catch (error) {
                        retryableFailure(error);
                    }
                });
            },
            proofApplicationSlotHash: prepared.proofApplicationSlotHash,
        });
    }

    #openActionStateVerifierSession(
        input: BrowserActionStateVerifierSessionInput,
    ): VerificationResult<string> {
        if (typeof input !== 'object' || input === null) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The action state-verifier session input must be an object.',
            );
        }
        const activeLease = this.#requireActiveLease();
        const canonicalRosterBytes = copyBoundedBytes(
            input.canonicalRosterBytes,
            'Canonical roster bytes',
        );
        const opened = openStateVerifierSession({
            configuration: {
                actionContextHash: activeLease.binding.actionContextHash,
                canonicalRosterBytes,
                ceremonyContextHash: activeLease.binding.ceremonyContextHash,
                suiteIdentifier: activeLease.binding.suiteId,
            },
            kernel: this.#kernel,
        });
        if (!opened.isValid) {
            return opened;
        }
        const identifier = this.#issueOpaqueWorkerIdentifier();
        this.#stateVerifierSessions.set(identifier, {
            canonicalRosterBytes,
            session: opened.value,
        });
        return Object.freeze({ isValid: true, value: identifier });
    }

    #verifyActionStateReservation(
        input: BrowserActionStateReservationVerificationInput,
    ): VerificationResult<string> {
        if (typeof input !== 'object' || input === null) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The action state-reservation input must be an object.',
            );
        }
        if (
            input.capabilityKind ===
            stateCapabilityKinds.setupActionRandomnessRoot
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'Action-randomness reservations must be verified against the retained commitment.',
            );
        }
        const sessionIdentifier = requireOpaqueWorkerIdentifier(
            input.stateVerifierSessionIdentifier,
            'State-verifier session identifier',
        );
        const session = this.#requireStateVerifierSession(sessionIdentifier);
        const verified = session.verifyReservation({
            canonicalReservationIntentCarrier: copyBoundedBytes(
                input.canonicalReservationIntentCarrier,
                'Canonical state-reservation intent carrier',
            ),
            canonicalStateCertificate: copyBoundedBytes(
                input.canonicalStateCertificate,
                'Canonical state certificate',
            ),
            capabilityKind: input.capabilityKind,
            expectedAuthorizationHash: copyExactBytes(
                input.expectedAuthorizationHash,
                foundationHashByteLength,
                'Expected state authorization hash',
            ),
            subjectParticipantIdentity: copyExactBytes(
                input.subjectParticipantIdentity,
                foundationHashByteLength,
                'State subject participant identity',
            ),
        });
        if (!verified.isValid) {
            return verified;
        }
        const identifier = this.#issueOpaqueWorkerIdentifier();
        this.#stateObjects.set(identifier, {
            capabilityKind: input.capabilityKind,
            kind: 'reservation',
            sessionIdentifier,
            subjectParticipantIdentity:
                input.subjectParticipantIdentity.slice(),
            value: verified.value,
        });
        return Object.freeze({ isValid: true, value: identifier });
    }

    #verifyActionRandomnessReservation(
        input: BrowserActionRandomnessReservationVerificationInput,
    ): VerificationResult<string> {
        if (typeof input !== 'object' || input === null) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The action-randomness reservation input must be an object.',
            );
        }
        const stateVerifierSessionIdentifier = requireOpaqueWorkerIdentifier(
            input.stateVerifierSessionIdentifier,
            'State-verifier session identifier',
        );
        const stateVerifierSession = this.#requireStateVerifierSessionRecord(
            stateVerifierSessionIdentifier,
        );
        const actionRandomnessSessionHandle =
            this.#requireActionRandomnessSession(
                input.actionRandomnessSessionIdentifier,
            );
        const activeBinding = this.#requireActiveLease().binding;
        let expectedAuthorizationHash: Uint8Array<ArrayBuffer> | undefined;
        try {
            expectedAuthorizationHash = this.#runActionRandomnessCommand(
                actionRandomnessCommandIdentifiers.setupActionRandomnessAuthorization,
                concatenateBytes(
                    encodeUnsigned32(actionRandomnessSessionHandle),
                    stateVerifierSession.canonicalRosterBytes,
                ),
                'derive the action-randomness reservation authorization',
                'runtime',
            );
            if (
                expectedAuthorizationHash.byteLength !==
                foundationHashByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned a malformed reservation authorization.',
                );
            }
            const verified = stateVerifierSession.session.verifyReservation({
                canonicalReservationIntentCarrier: copyBoundedBytes(
                    input.canonicalReservationIntentCarrier,
                    'Canonical action-randomness reservation intent carrier',
                ),
                canonicalStateCertificate: copyBoundedBytes(
                    input.canonicalStateCertificate,
                    'Canonical state certificate',
                ),
                capabilityKind: stateCapabilityKinds.setupActionRandomnessRoot,
                expectedAuthorizationHash,
                subjectParticipantIdentity: activeBinding.participantId.slice(),
            });
            if (!verified.isValid) {
                return verified;
            }
            const identifier = this.#issueOpaqueWorkerIdentifier();
            this.#stateObjects.set(identifier, {
                capabilityKind: stateCapabilityKinds.setupActionRandomnessRoot,
                kind: 'reservation',
                sessionIdentifier: stateVerifierSessionIdentifier,
                subjectParticipantIdentity: activeBinding.participantId.slice(),
                value: verified.value,
            });
            return Object.freeze({ isValid: true, value: identifier });
        } finally {
            expectedAuthorizationHash?.fill(0);
        }
    }

    #produceActionRandomnessReservationIntent(
        input: BrowserActionRandomnessReservationIntentProductionInput,
    ): VerificationResult<BrowserProducedActionRandomnessReservationIntent> {
        if (
            typeof input !== 'object' ||
            input === null ||
            typeof input.signatureOperation !== 'object' ||
            input.signatureOperation === null ||
            typeof input.signatureOperation.signStateObjectMessage !==
                'function'
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The action-randomness reservation-intent production input is invalid.',
            );
        }
        const stateVerifierSessionIdentifier = requireOpaqueWorkerIdentifier(
            input.stateVerifierSessionIdentifier,
            'State-verifier session identifier',
        );
        const session = this.#requireStateVerifierSession(
            stateVerifierSessionIdentifier,
        );
        const actionRandomnessHandle = this.#requireActionRandomnessSession(
            input.actionRandomnessSessionIdentifier,
        );
        const produced =
            produceSetupActionRandomnessReservationIntentFromRetainedKernelHandle(
                {
                    actionRandomnessHandle,
                    session,
                    signatureOperation: input.signatureOperation,
                },
            );
        if (!produced.isValid) {
            return produced;
        }
        let identifier: string | undefined;
        try {
            identifier = this.#issueOpaqueWorkerIdentifier();
            this.#stateObjects.set(identifier, {
                capabilityKind: stateCapabilityKinds.setupActionRandomnessRoot,
                kind: 'reservation-intent',
                sessionIdentifier: stateVerifierSessionIdentifier,
                subjectParticipantIdentity:
                    this.#requireActiveLease().binding.participantId.slice(),
                value: produced.value.verifiedIntent,
            });
            return Object.freeze({
                isValid: true,
                value: Object.freeze({
                    canonicalReservationIntentCarrier:
                        produced.value.canonicalReservationIntentCarrier.slice(),
                    stateIntentIdentifier: identifier,
                }),
            });
        } catch (operationFailure) {
            if (identifier !== undefined) {
                this.#stateObjects.delete(identifier);
            }
            const released = session.releaseVerifiedObject(
                produced.value.verifiedIntent,
            );
            if (!released.isValid) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'Registering and releasing a produced state reservation intent both failed.',
                    Object.freeze({
                        cleanupRefusalReason: released.refusalReason,
                        operationFailure,
                    }),
                );
            }
            throw operationFailure;
        }
    }

    #verifyActionRandomnessReservationIntentForWitness(
        input: BrowserActionRandomnessReservationIntentWitnessVerificationInput,
    ): VerificationResult<string> {
        if (typeof input !== 'object' || input === null) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The witnessed action-randomness reservation intent is invalid.',
            );
        }
        const stateVerifierSessionIdentifier = requireOpaqueWorkerIdentifier(
            input.stateVerifierSessionIdentifier,
            'State-verifier session identifier',
        );
        const session = this.#requireStateVerifierSession(
            stateVerifierSessionIdentifier,
        );
        const canonicalReservationIntentCarrier = copyBoundedBytes(
            input.canonicalReservationIntentCarrier,
            'Canonical action-randomness reservation intent carrier',
        );
        const subjectParticipantIdentity = copyExactBytes(
            input.subjectParticipantIdentity,
            foundationHashByteLength,
            'State subject participant identity',
        );
        try {
            const verified =
                session.verifySetupActionRandomnessIntentForWitness({
                    canonicalReservationIntentCarrier,
                    subjectParticipantIdentity,
                });
            if (!verified.isValid) {
                return verified;
            }
            let identifier: string | undefined;
            try {
                identifier = this.#issueOpaqueWorkerIdentifier();
                this.#stateObjects.set(identifier, {
                    capabilityKind:
                        stateCapabilityKinds.setupActionRandomnessRoot,
                    kind: 'reservation-intent',
                    sessionIdentifier: stateVerifierSessionIdentifier,
                    subjectParticipantIdentity:
                        subjectParticipantIdentity.slice(),
                    value: verified.value,
                });
                return Object.freeze({ isValid: true, value: identifier });
            } catch (operationFailure) {
                if (identifier !== undefined) {
                    this.#stateObjects.delete(identifier);
                }
                const released = session.releaseVerifiedObject(verified.value);
                if (!released.isValid) {
                    throw new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        'Registering and releasing a witnessed state reservation intent both failed.',
                        Object.freeze({
                            cleanupRefusalReason: released.refusalReason,
                            operationFailure,
                        }),
                    );
                }
                throw operationFailure;
            }
        } finally {
            canonicalReservationIntentCarrier.fill(0);
            subjectParticipantIdentity.fill(0);
        }
    }

    #produceActionRandomnessReservationWitnessVote(
        input: BrowserActionRandomnessReservationWitnessVoteProductionInput,
    ): VerificationResult<Uint8Array> {
        if (
            typeof input !== 'object' ||
            input === null ||
            typeof input.signatureOperation !== 'object' ||
            input.signatureOperation === null ||
            typeof input.signatureOperation.signStateObjectMessage !==
                'function'
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The state witness-vote production input is invalid.',
            );
        }
        const intent = this.#requireStateReservationIntent(
            input.stateIntentIdentifier,
        );
        const witnessParticipantIdentity = copyExactBytes(
            input.witnessParticipantIdentity,
            foundationHashByteLength,
            'State witness participant identity',
        );
        try {
            if (
                !byteArraysEqual(
                    witnessParticipantIdentity,
                    this.#requireActiveLease().binding.participantId,
                )
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The state witness identity does not belong to this worker-owned participant.',
                );
            }
            return constructVerifiedStateWitnessVoteCarrierForWorker({
                session: this.#requireStateVerifierSession(
                    intent.sessionIdentifier,
                ),
                signatureOperation: input.signatureOperation,
                verifiedIntent: intent.value,
                witnessParticipantIdentity,
            });
        } finally {
            witnessParticipantIdentity.fill(0);
        }
    }

    #certifyActionRandomnessReservation(
        input: BrowserActionRandomnessReservationCertificationInput,
    ): VerificationResult<BrowserProducedActionRandomnessReservation> {
        if (
            typeof input !== 'object' ||
            input === null ||
            !Array.isArray(input.untrustedVoteCarriers)
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The action-randomness reservation certification input is invalid.',
            );
        }
        const stateIntentIdentifier = requireOpaqueWorkerIdentifier(
            input.stateIntentIdentifier,
            'State reservation-intent identifier',
        );
        const intent = this.#requireStateReservationIntent(
            stateIntentIdentifier,
        );
        if (
            !byteArraysEqual(
                intent.subjectParticipantIdentity,
                this.#requireActiveLease().binding.participantId,
            )
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'Only the worker-owned subject can certify its produced state reservation intent.',
            );
        }
        const session = this.#requireStateVerifierSession(
            intent.sessionIdentifier,
        );
        const canonicalVoteCarriers = input.untrustedVoteCarriers.map(
            (carrier) =>
                copyBoundedBytes(
                    carrier,
                    'Canonical state witness-vote carrier',
                ),
        );
        try {
            const certified =
                session.certifyReservationIntentFromUntrustedVoteCarriers({
                    untrustedVoteCarriers: canonicalVoteCarriers.map(
                        (canonicalCarrier) => ({ canonicalCarrier }),
                    ),
                    verifiedIntent: intent.value,
                });
            if (!certified.isValid) {
                return certified;
            }
            this.#stateObjects.delete(stateIntentIdentifier);
            intent.subjectParticipantIdentity.fill(0);
            let stateReservationIdentifier: string | undefined;
            try {
                stateReservationIdentifier =
                    this.#issueOpaqueWorkerIdentifier();
                this.#stateObjects.set(stateReservationIdentifier, {
                    capabilityKind:
                        stateCapabilityKinds.setupActionRandomnessRoot,
                    kind: 'reservation',
                    sessionIdentifier: intent.sessionIdentifier,
                    subjectParticipantIdentity:
                        this.#requireActiveLease().binding.participantId.slice(),
                    value: certified.value.verifiedReservation,
                });
                return Object.freeze({
                    isValid: true,
                    value: Object.freeze({
                        canonicalStateCertificate:
                            certified.value.canonicalStateCertificate.slice(),
                        stateReservationIdentifier,
                    }),
                });
            } catch (operationFailure) {
                if (stateReservationIdentifier !== undefined) {
                    this.#stateObjects.delete(stateReservationIdentifier);
                }
                const released = session.releaseVerifiedObject(
                    certified.value.verifiedReservation,
                );
                if (!released.isValid) {
                    throw new BrowserActionStorageCustodyError(
                        'OwnedWorkerFailure',
                        'Registering and releasing a produced state reservation both failed.',
                        Object.freeze({
                            cleanupRefusalReason: released.refusalReason,
                            operationFailure,
                        }),
                    );
                }
                throw operationFailure;
            }
        } finally {
            for (const canonicalVoteCarrier of canonicalVoteCarriers) {
                canonicalVoteCarrier.fill(0);
            }
        }
    }

    #releaseActionStateObject(identifier: string): void {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            identifier,
            'State object identifier',
        );
        const stateObject = this.#stateObjects.get(copiedIdentifier);
        if (stateObject === undefined) {
            return;
        }
        const session = this.#requireStateVerifierSession(
            stateObject.sessionIdentifier,
        );
        const released = session.releaseVerifiedObject(stateObject.value);
        if (!released.isValid) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                `The state verifier refused object release: ${released.refusalReason}.`,
            );
        }
        stateObject.subjectParticipantIdentity.fill(0);
        this.#stateObjects.delete(copiedIdentifier);
    }

    #durableBindingForStateObject(
        identifier: string,
    ): VerificationResult<VerifiedStateDurableBinding> {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            identifier,
            'State object identifier',
        );
        const stateObject = this.#stateObjects.get(copiedIdentifier);
        if (stateObject === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The verified state object is unavailable in this worker.',
            );
        }
        const session = this.#requireStateVerifierSession(
            stateObject.sessionIdentifier,
        );
        return session.durableBindingFor(stateObject.value);
    }

    #closeActionStateVerifierSession(identifier: string): void {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            identifier,
            'State-verifier session identifier',
        );
        const sessionRecord = this.#stateVerifierSessions.get(copiedIdentifier);
        if (sessionRecord === undefined) {
            return;
        }
        sessionRecord.session.cancel();
        sessionRecord.canonicalRosterBytes.fill(0);
        this.#stateVerifierSessions.delete(copiedIdentifier);
        for (const [stateObjectIdentifier, stateObject] of this.#stateObjects) {
            if (stateObject.sessionIdentifier === copiedIdentifier) {
                stateObject.subjectParticipantIdentity.fill(0);
                this.#stateObjects.delete(stateObjectIdentifier);
            }
        }
    }

    #createAndSealActionRandomness(
        input: WorkerActionRandomnessRecordContext,
    ): WorkerSealedActionRandomnessSession {
        const activeLease = this.#requireActiveLease();
        const encodedRecordContext = encodeActionRandomnessRecordContext(
            activeLease.binding,
            input,
        );
        if (
            this.#actionRandomnessRootMintConsumed ||
            this.#actionRandomnessSessionAcquisitionConsumed
        ) {
            encodedRecordContext.fill(0);
            throw new BrowserActionStorageCustodyError(
                'Conflict',
                'The active storage root has already consumed its one action-randomness mint.',
            );
        }
        this.#actionRandomnessRootMintConsumed = true;
        this.#actionRandomnessSessionAcquisitionConsumed = true;
        let actionRoot: Uint8Array<ArrayBuffer> | undefined;
        let nonce: Uint8Array<ArrayBuffer> | undefined;
        let output: Uint8Array<ArrayBuffer> | undefined;
        let sessionHandle = 0;
        let sessionRetained = false;
        try {
            actionRoot = this.#randomBytes(
                actionRandomnessRootByteLength,
                'action-randomness root',
            );
            nonce = this.#randomBytes(
                localRecordNonceByteLength,
                'action-randomness record nonce',
            );
            output = this.#runActionRandomnessCommand(
                actionRandomnessCommandIdentifiers.createAndSeal,
                concatenateBytes(
                    this.#leaseCommandInput(activeLease),
                    actionRoot,
                    encodedRecordContext,
                    nonce,
                ),
                'create and seal action randomness',
                'recordSeal',
            );
            if (
                output.byteLength <=
                handleByteLength + foundationHashByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned malformed sealed-session metadata.',
                );
            }
            sessionHandle = decodeUnsigned32(output, 0);
            if (sessionHandle === 0) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned a zero session handle.',
                );
            }
            const sessionIdentifier = this.#issueOpaqueWorkerIdentifier();
            const retainedCommitment = output.slice(
                handleByteLength,
                handleByteLength + foundationHashByteLength,
            );
            this.#actionRandomnessSessions.set(sessionIdentifier, {
                actionRandomnessCommitment: retainedCommitment,
                handle: sessionHandle,
            });
            sessionRetained = true;
            return Object.freeze({
                actionRandomnessCommitment: output.slice(
                    handleByteLength,
                    handleByteLength + foundationHashByteLength,
                ),
                actionRandomnessSessionIdentifier: sessionIdentifier,
                canonicalEnvelope: output.slice(
                    handleByteLength + foundationHashByteLength,
                ),
            });
        } catch (error) {
            if (sessionHandle !== 0 && !sessionRetained) {
                this.#closeRawActionRandomness(sessionHandle);
            }
            throw error;
        } finally {
            actionRoot?.fill(0);
            encodedRecordContext.fill(0);
            nonce?.fill(0);
            output?.fill(0);
        }
    }

    #openSealedActionRandomness(
        input: WorkerActionRandomnessRecordContext &
            Readonly<{
                actionRandomnessCommitment: Uint8Array;
                canonicalEnvelope: Uint8Array;
            }>,
    ): BrowserOpenedActionRandomnessSession {
        if (
            !(input.canonicalEnvelope instanceof Uint8Array) ||
            input.canonicalEnvelope.byteLength === 0 ||
            input.canonicalEnvelope.byteLength > maximumCommandByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The sealed action-randomness envelope has an unsupported length.',
            );
        }
        const activeLease = this.#requireActiveLease();
        const expectedCommitment = copyExactBytes(
            input.actionRandomnessCommitment,
            foundationHashByteLength,
            'Action-randomness commitment',
        );
        const encodedRecordContext = encodeActionRandomnessRecordContext(
            activeLease.binding,
            input,
        );
        if (this.#actionRandomnessSessionAcquisitionConsumed) {
            expectedCommitment.fill(0);
            encodedRecordContext.fill(0);
            throw new BrowserActionStorageCustodyError(
                'Conflict',
                'The active storage root already has or consumed an action-randomness session.',
            );
        }
        this.#actionRandomnessSessionAcquisitionConsumed = true;
        let output: Uint8Array<ArrayBuffer> | undefined;
        let sessionHandle = 0;
        let sessionRetained = false;
        try {
            output = this.#runActionRandomnessCommand(
                actionRandomnessCommandIdentifiers.openSealed,
                concatenateBytes(
                    this.#leaseCommandInput(activeLease),
                    expectedCommitment,
                    encodedRecordContext,
                    input.canonicalEnvelope,
                ),
                'open sealed action randomness',
                'recordOpen',
            );
            if (
                output.byteLength !==
                handleByteLength + foundationHashByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned malformed reopened-session metadata.',
                );
            }
            sessionHandle = decodeUnsigned32(output, 0);
            const commitment = output.slice(handleByteLength);
            if (
                sessionHandle === 0 ||
                !byteArraysEqual(commitment, expectedCommitment)
            ) {
                commitment.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned inconsistent reopened-session metadata.',
                );
            }
            const sessionIdentifier = this.#issueOpaqueWorkerIdentifier();
            this.#actionRandomnessSessions.set(sessionIdentifier, {
                actionRandomnessCommitment: commitment.slice(),
                handle: sessionHandle,
            });
            sessionRetained = true;
            return Object.freeze({
                actionRandomnessCommitment: commitment,
                actionRandomnessSessionIdentifier: sessionIdentifier,
            });
        } catch (error) {
            if (sessionHandle !== 0 && !sessionRetained) {
                this.#closeRawActionRandomness(sessionHandle);
            }
            throw error;
        } finally {
            expectedCommitment.fill(0);
            encodedRecordContext.fill(0);
            output?.fill(0);
        }
    }

    #closeActionRandomness(sessionIdentifier: string): void {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            sessionIdentifier,
            'Action-randomness session identifier',
        );
        const sessionRecord =
            this.#actionRandomnessSessions.get(copiedIdentifier);
        if (sessionRecord === undefined) {
            return;
        }
        this.#closeRawActionRandomness(sessionRecord.handle);
        sessionRecord.actionRandomnessCommitment.fill(0);
        this.#actionRandomnessSessions.delete(copiedIdentifier);
    }

    #openClosedSetupMailboxRandomness(
        input: WorkerSetupMailboxRandomnessInput,
    ): ClosedWorkerSetupMailboxRandomnessOperations {
        if (typeof input !== 'object' || input === null) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The setup-mailbox randomness input must be an object.',
            );
        }
        const actionRandomnessSessionIdentifier = requireOpaqueWorkerIdentifier(
            input.actionRandomnessSessionIdentifier,
            'Action-randomness session identifier',
        );
        const stateReservationIdentifier = requireOpaqueWorkerIdentifier(
            input.stateReservationIdentifier,
            'State-reservation identifier',
        );
        const initialBinding = this.#requireActiveLease().binding;
        const actionRandomnessSessionHandle =
            this.#requireActionRandomnessSession(
                actionRandomnessSessionIdentifier,
            );
        const initialReservation = this.#requireStateReservation(
            stateReservationIdentifier,
            stateCapabilityKinds.setupActionRandomnessRoot,
            initialBinding,
        );
        const stateVerifierSession = this.#requireStateVerifierSessionRecord(
            initialReservation.sessionIdentifier,
        );
        const sourceMailboxEncapsulationKey = copyExactBytes(
            input.sourceMailboxEncapsulationKey,
            mlKem768EncapsulationKeyByteLength,
            'Source mailbox encapsulation key',
        );
        const sourceSigningVerificationKey = copyExactBytes(
            input.signing.verificationKey,
            mlDsa65VerificationKeyByteLength,
            'Source signing verification key',
        );
        const reservationAuthorization = this.#reservationAuthorizationBytes(
            initialReservation.value,
        );
        let rosterHashBytes: Uint8Array<ArrayBuffer>;
        try {
            const validationOutput = this.#runActionRandomnessCommand(
                actionRandomnessCommandIdentifiers.validateSetupMailboxSourceKeys,
                concatenateBytes(
                    encodeUnsigned32(actionRandomnessSessionHandle),
                    reservationAuthorization,
                    sourceSigningVerificationKey,
                    sourceMailboxEncapsulationKey,
                    stateVerifierSession.canonicalRosterBytes,
                ),
                'validate setup-mailbox source keys against the frozen roster',
                'runtime',
            );
            if (validationOutput.byteLength !== foundationHashByteLength) {
                validationOutput.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned a malformed frozen-roster hash.',
                );
            }
            rosterHashBytes = validationOutput;
        } finally {
            reservationAuthorization.fill(0);
            sourceMailboxEncapsulationKey.fill(0);
            sourceSigningVerificationKey.fill(0);
        }
        const actionContextHash = bytesToHex(initialBinding.actionContextHash);
        const ceremonyContextHash = bytesToHex(
            initialBinding.ceremonyContextHash,
        );
        const rosterHash = bytesToHex(rosterHashBytes);
        const sourceParticipantId = bytesToHex(initialBinding.participantId);
        const suiteId = bytesToHex(initialBinding.suiteId);
        let revoked = false;

        const requireSlot = (
            setupMailboxSlot: SetupMailboxSlot,
            suppliedSlotHash: ProtocolHash,
        ): Readonly<{
            reservation: Extract<
                WorkerStateObject,
                Readonly<{ kind: 'reservation' }>
            >;
            sessionHandle: number;
            slotHashBytes: Uint8Array<ArrayBuffer>;
        }> => {
            if (revoked) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidState',
                    'The setup-mailbox randomness capability was revoked.',
                );
            }
            const binding = this.#requireActiveLease().binding;
            const sessionHandle = this.#requireActionRandomnessSession(
                actionRandomnessSessionIdentifier,
            );
            const reservation = this.#requireStateReservation(
                stateReservationIdentifier,
                stateCapabilityKinds.setupActionRandomnessRoot,
                binding,
            );
            if (
                typeof setupMailboxSlot !== 'object' ||
                setupMailboxSlot === null ||
                setupMailboxSlot.suiteId !== suiteId ||
                setupMailboxSlot.ceremonyContextHash !== ceremonyContextHash ||
                setupMailboxSlot.actionContextHash !== actionContextHash ||
                setupMailboxSlot.rosterHash !== rosterHash ||
                setupMailboxSlot.sourceParticipantId !== sourceParticipantId ||
                this.#kernel.deriveSetupMailboxSlotHash(setupMailboxSlot) !==
                    suppliedSlotHash
            ) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidInput',
                    'The setup-mailbox slot does not match the worker-owned action randomness and frozen roster.',
                );
            }
            return Object.freeze({
                reservation,
                sessionHandle,
                slotHashBytes: protocolHashBytes(
                    suppliedSlotHash,
                    'Setup-mailbox slot hash',
                ),
            });
        };

        return Object.freeze({
            actionContextHash,
            ceremonyContextHash,
            rosterHash,
            sourceParticipantId,
            suiteId,
            encapsulate: ({
                recipientEncapsulationKey,
                setupMailboxSlot,
                setupMailboxSlotHash,
            }) => {
                const { reservation, sessionHandle, slotHashBytes } =
                    requireSlot(setupMailboxSlot, setupMailboxSlotHash);
                const slotReservationAuthorization =
                    this.#reservationAuthorizationBytes(reservation.value);
                const copiedRecipientEncapsulationKey = copyExactBytes(
                    recipientEncapsulationKey,
                    mlKem768EncapsulationKeyByteLength,
                    'Setup-mailbox recipient encapsulation key',
                );
                const recipientParticipantIdentityBytes = protocolHashBytes(
                    setupMailboxSlot.recipientParticipantId,
                    'Setup-mailbox recipient participant identity',
                );
                let output: Uint8Array<ArrayBuffer> | undefined;
                try {
                    output = this.#runActionRandomnessCommand(
                        actionRandomnessCommandIdentifiers.setupMailboxEncapsulate,
                        concatenateBytes(
                            encodeUnsigned32(sessionHandle),
                            slotReservationAuthorization,
                            rosterHashBytes,
                            slotHashBytes,
                            recipientParticipantIdentityBytes,
                            copiedRecipientEncapsulationKey,
                        ),
                        'encapsulate a reset-safe setup-mailbox shared secret',
                        'runtime',
                    );
                    if (
                        output.byteLength !==
                        attemptIdentifierByteLength +
                            mlKem768CiphertextByteLength +
                            mlKem768SharedSecretByteLength
                    ) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'The WASM action-randomness kernel returned a malformed setup-mailbox encapsulation.',
                        );
                    }
                    return Object.freeze({
                        ciphertext: output.slice(
                            attemptIdentifierByteLength,
                            attemptIdentifierByteLength +
                                mlKem768CiphertextByteLength,
                        ),
                        envelopeAttemptIdentifier: output.slice(
                            0,
                            attemptIdentifierByteLength,
                        ),
                        sharedSecret: output.slice(
                            attemptIdentifierByteLength +
                                mlKem768CiphertextByteLength,
                        ),
                    });
                } finally {
                    copiedRecipientEncapsulationKey.fill(0);
                    recipientParticipantIdentityBytes.fill(0);
                    slotReservationAuthorization.fill(0);
                    slotHashBytes.fill(0);
                    output?.fill(0);
                }
            },
            signEnvelope: ({
                envelopeHash,
                setupMailboxSlot,
                setupMailboxSlotHash,
            }) => {
                const { reservation, sessionHandle, slotHashBytes } =
                    requireSlot(setupMailboxSlot, setupMailboxSlotHash);
                const slotReservationAuthorization =
                    this.#reservationAuthorizationBytes(reservation.value);
                const envelopeHashBytes = protocolHashBytes(
                    envelopeHash,
                    'Setup-mailbox envelope hash',
                );
                let hedge: Uint8Array<ArrayBuffer> | undefined;
                let providerSignature: Uint8Array | undefined;
                let providerContext: Uint8Array | undefined;
                let providerHedge: Uint8Array | undefined;
                let providerMessage: Uint8Array | undefined;
                try {
                    hedge = this.#runActionRandomnessCommand(
                        actionRandomnessCommandIdentifiers.setupMailboxSignatureHedge,
                        concatenateBytes(
                            encodeUnsigned32(sessionHandle),
                            slotReservationAuthorization,
                            rosterHashBytes,
                            envelopeHashBytes,
                        ),
                        'sign a reset-safe setup-mailbox envelope',
                        'runtime',
                    );
                    if (hedge.byteLength !== attemptIdentifierByteLength) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'The WASM action-randomness kernel returned a malformed setup-mailbox signature hedge.',
                        );
                    }
                    providerContext = setupMailboxSignatureContext.slice();
                    providerHedge = hedge.slice();
                    providerMessage = envelopeHashBytes.slice();
                    providerSignature = input.signing.signClosedMessage({
                        context: providerContext,
                        hedge: providerHedge,
                        message: providerMessage,
                    });
                    return copyExactBytes(
                        providerSignature,
                        mlDsa65SignatureByteLength,
                        'Setup-mailbox source signature',
                    );
                } finally {
                    envelopeHashBytes.fill(0);
                    hedge?.fill(0);
                    providerContext?.fill(0);
                    providerHedge?.fill(0);
                    providerMessage?.fill(0);
                    providerSignature?.fill(0);
                    slotReservationAuthorization.fill(0);
                    slotHashBytes.fill(0);
                }
            },
            signSetupObject: ({ signatureMessageHash }) => {
                if (revoked) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidState',
                        'The setup-object signing capability was revoked.',
                    );
                }
                const binding = this.#requireActiveLease().binding;
                const sessionHandle = this.#requireActionRandomnessSession(
                    actionRandomnessSessionIdentifier,
                );
                const reservation = this.#requireStateReservation(
                    stateReservationIdentifier,
                    stateCapabilityKinds.setupActionRandomnessRoot,
                    binding,
                );
                const setupObjectReservationAuthorization =
                    this.#reservationAuthorizationBytes(reservation.value);
                const signatureMessageHashBytes = protocolHashBytes(
                    signatureMessageHash,
                    'Setup-object signature-message hash',
                );
                let hedge: Uint8Array<ArrayBuffer> | undefined;
                let providerContext: Uint8Array | undefined;
                let providerHedge: Uint8Array | undefined;
                let providerMessage: Uint8Array | undefined;
                let providerSignature: Uint8Array | undefined;
                try {
                    hedge = this.#runActionRandomnessCommand(
                        actionRandomnessCommandIdentifiers.setupObjectSignatureHedge,
                        concatenateBytes(
                            encodeUnsigned32(sessionHandle),
                            setupObjectReservationAuthorization,
                            rosterHashBytes,
                            signatureMessageHashBytes,
                        ),
                        'sign a reset-safe setup object',
                        'runtime',
                    );
                    if (hedge.byteLength !== attemptIdentifierByteLength) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'The WASM action-randomness kernel returned a malformed setup-object signature hedge.',
                        );
                    }
                    providerContext = objectSignatureContext.slice();
                    providerHedge = hedge.slice();
                    providerMessage = signatureMessageHashBytes.slice();
                    providerSignature = input.signing.signClosedMessage({
                        context: providerContext,
                        hedge: providerHedge,
                        message: providerMessage,
                    });
                    return copyExactBytes(
                        providerSignature,
                        mlDsa65SignatureByteLength,
                        'Setup-object source signature',
                    );
                } finally {
                    hedge?.fill(0);
                    providerContext?.fill(0);
                    providerHedge?.fill(0);
                    providerMessage?.fill(0);
                    providerSignature?.fill(0);
                    setupObjectReservationAuthorization.fill(0);
                    signatureMessageHashBytes.fill(0);
                }
            },
            revoke: () => {
                if (revoked) {
                    return;
                }
                revoked = true;
                rosterHashBytes.fill(0);
            },
        });
    }

    #closeRawActionRandomness(sessionHandle: number): void {
        const output = this.#runActionRandomnessCommand(
            actionRandomnessCommandIdentifiers.close,
            encodeUnsigned32(sessionHandle),
            'close action randomness',
            'runtime',
        );
        try {
            if (output.byteLength !== 0) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness close command returned unexpected output.',
                );
            }
        } finally {
            output.fill(0);
        }
    }

    #closeAllActionRandomness(): void {
        for (const sessionIdentifier of [
            ...this.#actionRandomnessSessions.keys(),
        ]) {
            this.#closeActionRandomness(sessionIdentifier);
        }
    }

    #closeAllAuthenticatedRepairProtectionSessions(): void {
        for (const identifier of [
            ...this.#authenticatedRepairProtectionSessions.keys(),
        ]) {
            this.#closeAuthenticatedRepairProtection(identifier);
        }
    }

    #closeAllStateVerifierSessions(): void {
        for (const sessionIdentifier of [
            ...this.#stateVerifierSessions.keys(),
        ]) {
            this.#closeActionStateVerifierSession(sessionIdentifier);
        }
    }

    #deriveTargetReleaseAttempt(
        input: BrowserTargetReleaseAttemptInput,
    ): BrowserActionProofAttemptBinding {
        if (typeof input !== 'object' || input === null) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The target-release attempt input must be an object.',
            );
        }
        const sessionHandle = this.#requireActionRandomnessSession(
            input.actionRandomnessSessionIdentifier,
        );
        const reservation = this.#requireStateReservation(
            input.stateReservationIdentifier,
            stateCapabilityKinds.targetRelease,
            this.#requireActiveLease().binding,
        );
        const reservationAuthorization = this.#reservationAuthorizationBytes(
            reservation.value,
        );
        try {
            return this.#parseProofAttemptOutput(
                this.#runActionRandomnessCommand(
                    actionRandomnessCommandIdentifiers.targetReleaseAttempt,
                    concatenateBytes(
                        encodeUnsigned32(sessionHandle),
                        reservationAuthorization,
                        encodeCanonicalUnsigned16(
                            input.rosterPosition,
                            'Target-release roster position',
                        ),
                    ),
                    'derive a target-release attempt',
                    'runtime',
                ),
            );
        } finally {
            reservationAuthorization.fill(0);
        }
    }

    #requireStateVerifierSession(identifier: string): StateVerifierSession {
        return this.#requireStateVerifierSessionRecord(identifier).session;
    }

    #requireStateVerifierSessionRecord(
        identifier: string,
    ): WorkerStateVerifierSession {
        const sessionRecord = this.#stateVerifierSessions.get(identifier);
        if (
            sessionRecord === undefined ||
            sessionRecord.session.state() !== 'active'
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The state-verifier session is closed or unavailable in this worker.',
            );
        }

        return sessionRecord;
    }

    #requireStateReservation(
        identifier: string,
        expectedCapabilityKind: number,
        binding: BrowserActionStorageRootBinding,
    ): Extract<WorkerStateObject, Readonly<{ kind: 'reservation' }>> {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            identifier,
            'State-reservation identifier',
        );
        const stateObject = this.#stateObjects.get(copiedIdentifier);
        if (
            stateObject === undefined ||
            stateObject.kind !== 'reservation' ||
            stateObject.capabilityKind !== expectedCapabilityKind ||
            !byteArraysEqual(
                stateObject.subjectParticipantIdentity,
                binding.participantId,
            ) ||
            !this.#stateVerifierSessions.has(stateObject.sessionIdentifier)
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The required matching state reservation is unavailable in this worker.',
            );
        }

        return stateObject;
    }

    #requireStateReservationIntent(
        identifier: string,
    ): Extract<WorkerStateObject, Readonly<{ kind: 'reservation-intent' }>> {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            identifier,
            'State reservation-intent identifier',
        );
        const stateObject = this.#stateObjects.get(copiedIdentifier);
        if (
            stateObject === undefined ||
            stateObject.kind !== 'reservation-intent' ||
            stateObject.capabilityKind !==
                stateCapabilityKinds.setupActionRandomnessRoot ||
            !this.#stateVerifierSessions.has(stateObject.sessionIdentifier)
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The required state reservation intent is unavailable in this worker.',
            );
        }
        return stateObject;
    }

    #reservationAuthorizationBytes(
        reservation: VerifiedStateReservation,
    ): Uint8Array<ArrayBuffer> {
        let authorization;
        try {
            authorization = resolveVerifiedStateReservationKernelAuthorization(
                reservation,
                this.#kernel,
            );
        } catch (error) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The state reservation is no longer active in this worker.',
                error,
            );
        }
        if (
            authorization.capabilityMemory !==
                this.#actionRandomnessContext.memory ||
            authorization.capabilityPointer <= 0 ||
            authorization.capabilityPointer + capabilityByteLength >
                authorization.capabilityMemory.buffer.byteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The state verifier returned malformed reservation authorization.',
            );
        }
        const bytes = new Uint8Array(
            handleByteLength + capabilityByteLength + handleByteLength,
        );
        const view = new DataView(bytes.buffer);
        view.setUint32(0, authorization.sessionHandle, true);
        bytes.set(
            new Uint8Array(
                authorization.capabilityMemory.buffer,
                authorization.capabilityPointer,
                capabilityByteLength,
            ),
            handleByteLength,
        );
        view.setUint32(
            handleByteLength + capabilityByteLength,
            authorization.reservationHandle,
            true,
        );

        return bytes;
    }

    #requireActionRandomnessSession(identifier: string): number {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            identifier,
            'Action-randomness session identifier',
        );
        const record = this.#actionRandomnessSessions.get(copiedIdentifier);
        if (record === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The action-randomness session is closed or unavailable in this worker.',
            );
        }

        return record.handle;
    }

    #parseProofAttemptOutput(
        output: Uint8Array<ArrayBuffer>,
    ): BrowserActionProofAttemptBinding {
        try {
            if (
                output.byteLength !==
                foundationHashByteLength + attemptIdentifierByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM action-randomness kernel returned malformed proof-attempt metadata.',
                );
            }

            return Object.freeze({
                applicationSlotHash: output.slice(0, foundationHashByteLength),
                attemptIdentifier: output.slice(foundationHashByteLength),
            });
        } finally {
            output.fill(0);
        }
    }

    #issueOpaqueWorkerIdentifier(): string {
        for (let attempt = 0; attempt < 16; attempt += 1) {
            const bytes = this.#randomBytes(
                attemptIdentifierByteLength,
                'opaque worker identifier',
            );
            const identifier = bytesToHex(bytes);
            bytes.fill(0);
            if (
                !this.#stateVerifierSessions.has(identifier) &&
                !this.#stateObjects.has(identifier) &&
                !this.#actionRandomnessSessions.has(identifier) &&
                !this.#authenticatedRepairProtectionSessions.has(identifier)
            ) {
                return identifier;
            }
        }
        throw new BrowserActionStorageCustodyError(
            'Unavailable',
            'Secure randomness repeatedly produced an existing worker identifier.',
        );
    }

    #deriveLocalRecordIdentifier(
        input:
            | BrowserLocalRecordIdentifierInput
            | ClosedWorkerCommonProofScratchRecordIdentifierInput,
        command: number = localStorageRootCommands.deriveRecordIdentifier,
    ): Uint8Array<ArrayBuffer> {
        const activeLease = this.#requireActiveLease();
        const encodedIdentifier = encodeLocalRecordIdentifierInput(input);
        const identifier = this.#runCommand(
            command,
            this.#leaseCommandInput(
                activeLease,
                encodeCanonicalUnsigned16(
                    encodedIdentifier.recordTypeCode,
                    'Local-record type',
                ),
                encodedIdentifier.context,
            ),
            'derive a local-record identifier',
            'recordSeal',
        );
        if (identifier.byteLength !== foundationHashByteLength) {
            identifier.fill(0);
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The WASM kernel returned a malformed local-record identifier.',
            );
        }

        return identifier;
    }

    #sealLocalRecord(
        input:
            | BrowserLocalRecordSealInput
            | (ClosedWorkerCommonProofScratchRecordSealInput &
                  Readonly<{ recordVersion: 0n }>),
        command: number = localStorageRootCommands.sealRecord,
    ): Uint8Array<ArrayBuffer> {
        if (
            typeof input !== 'object' ||
            input === null ||
            !(input.plaintext instanceof Uint8Array) ||
            input.plaintext.byteLength > maximumLocalRecordPlaintextByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                `The local-record plaintext must contain at most ${maximumLocalRecordPlaintextByteLength} bytes.`,
            );
        }
        const activeLease = this.#requireActiveLease();
        const nonce = this.#randomBytes(
            localRecordNonceByteLength,
            'local-record nonce',
        );
        try {
            const envelope = this.#runCommand(
                command,
                this.#leaseCommandInput(
                    activeLease,
                    encodeLocalRecordExpectedContext(input),
                    nonce,
                    input.plaintext,
                ),
                'seal a local record',
                'recordSeal',
            );
            if (envelope.byteLength === 0) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM kernel returned an empty local-record envelope.',
                );
            }

            return envelope;
        } finally {
            nonce.fill(0);
        }
    }

    #openLocalRecord(
        input:
            | BrowserLocalRecordOpenInput
            | (ClosedWorkerCommonProofScratchRecordOpenInput &
                  Readonly<{ recordVersion: 0n }>),
        command: number = localStorageRootCommands.openRecord,
    ): Uint8Array<ArrayBuffer> {
        if (
            typeof input !== 'object' ||
            input === null ||
            !(input.envelope instanceof Uint8Array) ||
            input.envelope.byteLength === 0 ||
            input.envelope.byteLength > maximumCommandByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The local-record envelope has an unsupported length.',
            );
        }
        const activeLease = this.#requireActiveLease();

        return this.#runCommand(
            command,
            this.#leaseCommandInput(
                activeLease,
                encodeLocalRecordExpectedContext(input),
                input.envelope,
            ),
            'open a local record',
            'recordOpen',
        );
    }

    #hashLocalRecordEnvelope(envelope: Uint8Array): Uint8Array<ArrayBuffer> {
        if (
            !(envelope instanceof Uint8Array) ||
            envelope.byteLength === 0 ||
            envelope.byteLength > maximumCommandByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The local-record envelope has an unsupported length.',
            );
        }
        const activeLease = this.#requireActiveLease();
        const envelopeHash = this.#runCommand(
            localStorageRootCommands.hashRecordEnvelope,
            this.#leaseCommandInput(activeLease, envelope),
            'hash a canonical local-record envelope',
            'recordHash',
        );
        if (envelopeHash.byteLength !== foundationHashByteLength) {
            envelopeHash.fill(0);
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The WASM kernel returned a malformed local-record envelope hash.',
            );
        }

        return envelopeHash;
    }

    #openActiveAuthenticatedRepairProtection(
        input: BrowserAuthenticatedRepairProtectionInput,
    ): WorkerOpenedBrowserAuthenticatedRepairProtection {
        if (
            typeof input !== 'object' ||
            input === null ||
            typeof input.namespace !== 'string' ||
            input.namespace.length > 64 ||
            !storageNamespacePattern.test(input.namespace)
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The authenticated-repair namespace must be lowercase kebab-case with at most 64 characters.',
            );
        }
        const runtimeBuildManifestHash = copyExactBytes(
            input.runtimeBuildManifestHash,
            foundationHashByteLength,
            'Authenticated-repair runtime build-manifest hash',
        );
        const namespaceBytes = repairTextEncoder.encode(input.namespace);
        if (namespaceBytes.byteLength === 0 || namespaceBytes.byteLength > 64) {
            runtimeBuildManifestHash.fill(0);
            namespaceBytes.fill(0);
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The authenticated-repair namespace has an unsupported encoded length.',
            );
        }
        const sessionIdentifier = this.#issueOpaqueWorkerIdentifier();
        try {
            const repairIdentity = this.#runCommand(
                localStorageRootCommands.deriveRepairIdentity,
                this.#authenticatedRepairCommandInput(
                    this.#requireActiveLease(),
                    runtimeBuildManifestHash,
                    namespaceBytes,
                ),
                'derive authenticated-repair identity',
                'runtime',
            );
            if (repairIdentity.byteLength !== foundationHashByteLength) {
                repairIdentity.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM kernel returned a malformed authenticated-repair identity.',
                );
            }
            this.#authenticatedRepairProtectionSessions.set(
                sessionIdentifier,
                Object.freeze({
                    namespaceBytes,
                    runtimeBuildManifestHash,
                }),
            );
            return Object.freeze({
                repairIdentity,
                repairProtectionSessionIdentifier: sessionIdentifier,
            });
        } catch (error) {
            namespaceBytes.fill(0);
            runtimeBuildManifestHash.fill(0);
            throw error;
        }
    }

    #sealAuthenticatedRepairHead(input: {
        plaintext: Uint8Array;
        repairProtectionSessionIdentifier: string;
    }): Uint8Array<ArrayBuffer> {
        const plaintext = copyBoundedBytes(
            input?.plaintext,
            'Authenticated-repair head plaintext',
        );
        const nonce = this.#randomBytes(
            localRecordNonceByteLength,
            'authenticated-repair head nonce',
        );
        try {
            return this.#runCommand(
                localStorageRootCommands.sealRepairHead,
                concatenateBytes(
                    this.#authenticatedRepairSessionCommandInput(
                        input.repairProtectionSessionIdentifier,
                    ),
                    nonce,
                    plaintext,
                ),
                'seal an authenticated-repair head',
                'recordSeal',
            );
        } finally {
            nonce.fill(0);
            plaintext.fill(0);
        }
    }

    #openAuthenticatedRepairHead(input: {
        canonicalEnvelope: Uint8Array;
        repairProtectionSessionIdentifier: string;
    }): Uint8Array<ArrayBuffer> {
        const canonicalEnvelope = copyBoundedBytes(
            input?.canonicalEnvelope,
            'Authenticated-repair head envelope',
        );
        try {
            return this.#runCommand(
                localStorageRootCommands.openRepairHead,
                concatenateBytes(
                    this.#authenticatedRepairSessionCommandInput(
                        input.repairProtectionSessionIdentifier,
                    ),
                    canonicalEnvelope,
                ),
                'open an authenticated-repair head',
                'recordOpen',
            );
        } finally {
            canonicalEnvelope.fill(0);
        }
    }

    #deriveAuthenticatedRepairHeadDigest(input: {
        sealedHeadBytes: Uint8Array;
        repairProtectionSessionIdentifier: string;
    }): Uint8Array<ArrayBuffer> {
        const sealedHeadBytes = copyBoundedBytes(
            input?.sealedHeadBytes,
            'Authenticated-repair sealed-head bytes',
        );
        try {
            const digest = this.#runCommand(
                localStorageRootCommands.digestRepairHead,
                concatenateBytes(
                    this.#authenticatedRepairSessionCommandInput(
                        input.repairProtectionSessionIdentifier,
                    ),
                    sealedHeadBytes,
                ),
                'derive an authenticated-repair head digest',
                'recordHash',
            );
            if (digest.byteLength !== foundationHashByteLength) {
                digest.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM kernel returned a malformed authenticated-repair head digest.',
                );
            }
            return digest;
        } finally {
            sealedHeadBytes.fill(0);
        }
    }

    #authenticatedRepairSessionCommandInput(
        identifier: string,
    ): Uint8Array<ArrayBuffer> {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            identifier,
            'Authenticated-repair protection session identifier',
        );
        const record =
            this.#authenticatedRepairProtectionSessions.get(copiedIdentifier);
        if (record === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The authenticated-repair protection session is closed or unavailable in this worker.',
            );
        }
        return this.#authenticatedRepairCommandInput(
            this.#requireActiveLease(),
            record.runtimeBuildManifestHash,
            record.namespaceBytes,
        );
    }

    #authenticatedRepairCommandInput(
        activeLease: RootLease,
        runtimeBuildManifestHash: Uint8Array,
        namespaceBytes: Uint8Array,
    ): Uint8Array<ArrayBuffer> {
        return this.#leaseCommandInput(
            activeLease,
            runtimeBuildManifestHash,
            encodeCanonicalUnsigned32(
                namespaceBytes.byteLength,
                'Authenticated-repair namespace length',
            ),
            namespaceBytes,
        );
    }

    #closeAuthenticatedRepairProtection(identifier: string): void {
        const copiedIdentifier = requireOpaqueWorkerIdentifier(
            identifier,
            'Authenticated-repair protection session identifier',
        );
        const record =
            this.#authenticatedRepairProtectionSessions.get(copiedIdentifier);
        if (record === undefined) {
            return;
        }
        record.namespaceBytes.fill(0);
        record.runtimeBuildManifestHash.fill(0);
        this.#authenticatedRepairProtectionSessions.delete(copiedIdentifier);
    }

    #prepareBrowserFoundationInitialization(
        input: WorkerBrowserFoundationInitializationPreparationInput,
    ): WorkerPreparedBrowserFoundationInitialization {
        const activeLease = this.#requireActiveLease();
        const copiedInput = copyBrowserFoundationInitializationInput(input);
        let actionRandomness:
            | WorkerPreparedBrowserFoundationInitialization['actionRandomness']
            | undefined;
        const witnessStateRecords: Array<
            WorkerPreparedBrowserFoundationInitialization['witnessStateRecords'][number]
        > = [];
        try {
            const subjectIdentityKeys = new Set<string>();
            for (const [
                bindingIndex,
                binding,
            ] of copiedInput.orderedWitnessBindings.entries()) {
                if (
                    !byteArraysEqual(
                        binding.witnessParticipantIdentity,
                        activeLease.binding.participantId,
                    )
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        `Witness provisioning binding ${String(bindingIndex)} is not witnessed by the local custody participant.`,
                    );
                }
                if (
                    byteArraysEqual(
                        binding.subjectParticipantIdentity,
                        activeLease.binding.participantId,
                    )
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        `Witness provisioning binding ${String(bindingIndex)} makes the local participant witness itself.`,
                    );
                }
                const subjectIdentityKey = bytesToHex(
                    binding.subjectParticipantIdentity,
                );
                if (subjectIdentityKeys.has(subjectIdentityKey)) {
                    throw new BrowserActionStorageCustodyError(
                        'Conflict',
                        'Foundation witness provisioning contains a repeated subject participant.',
                    );
                }
                subjectIdentityKeys.add(subjectIdentityKey);
            }

            const sealedActionRandomness = this.#createAndSealActionRandomness(
                copiedInput.actionRandomnessRecordContext,
            );
            const actionRandomnessLocalRecordIdentifier =
                this.#deriveLocalRecordIdentifier({
                    recordType: 'actionRandomness',
                });
            try {
                actionRandomness = Object.freeze({
                    ...sealedActionRandomness,
                    envelopeHash: this.#hashLocalRecordEnvelope(
                        sealedActionRandomness.canonicalEnvelope,
                    ),
                    localRecordIdentifier:
                        actionRandomnessLocalRecordIdentifier,
                });
            } catch (error) {
                actionRandomnessLocalRecordIdentifier.fill(0);
                sealedActionRandomness.actionRandomnessCommitment.fill(0);
                sealedActionRandomness.canonicalEnvelope.fill(0);
                this.#closeActionRandomness(
                    sealedActionRandomness.actionRandomnessSessionIdentifier,
                );
                throw error;
            }

            for (const [
                roleIndex,
                witnessBinding,
            ] of copiedInput.orderedWitnessBindings.entries()) {
                let canonicalRole: Uint8Array<ArrayBuffer> | undefined;
                let stateKey: Uint8Array<ArrayBuffer> | undefined;
                let authorizedEmptyPlaintext:
                    | Uint8Array<ArrayBuffer>
                    | undefined;
                let localRecordIdentifier: Uint8Array<ArrayBuffer> | undefined;
                let canonicalEnvelope: Uint8Array<ArrayBuffer> | undefined;
                try {
                    canonicalRole = encodeFoundationWitnessRole({
                        binding: activeLease.binding,
                        roleIndex,
                        runtimeBuildManifestHash:
                            copiedInput.runtimeBuildManifestHash,
                        witnessBinding,
                    });
                    stateKey = domainSeparatedHash(
                        foundationWitnessStateKeyDomain,
                        canonicalRole,
                        'Witness state key',
                    );
                    authorizedEmptyPlaintext =
                        encodeFoundationWitnessAuthorizedEmpty(canonicalRole);
                    const expectedContext = Object.freeze({
                        actionRandomnessCommitment:
                            actionRandomness.actionRandomnessCommitment,
                        identifierInput: Object.freeze({
                            recordType: 'witnessState' as const,
                            stateKey,
                        }),
                        recordVersion: 0n,
                    });
                    localRecordIdentifier = this.#deriveLocalRecordIdentifier(
                        expectedContext.identifierInput,
                    );
                    canonicalEnvelope = this.#sealLocalRecord({
                        ...expectedContext,
                        plaintext: authorizedEmptyPlaintext,
                    });
                    const envelopeHash =
                        this.#hashLocalRecordEnvelope(canonicalEnvelope);
                    witnessStateRecords.push(
                        Object.freeze({
                            authorizedEmptyPlaintext:
                                authorizedEmptyPlaintext.slice(),
                            canonicalEnvelope,
                            envelopeHash,
                            localRecordIdentifier,
                            roleIndex,
                            stateKey: stateKey.slice(),
                        }),
                    );
                    canonicalEnvelope = undefined;
                    localRecordIdentifier = undefined;
                } finally {
                    canonicalEnvelope?.fill(0);
                    localRecordIdentifier?.fill(0);
                    authorizedEmptyPlaintext?.fill(0);
                    stateKey?.fill(0);
                    canonicalRole?.fill(0);
                }
            }

            return Object.freeze({
                actionRandomness,
                witnessStateRecords: Object.freeze(witnessStateRecords),
            });
        } catch (error) {
            if (actionRandomness !== undefined) {
                this.#closeActionRandomness(
                    actionRandomness.actionRandomnessSessionIdentifier,
                );
                actionRandomness.actionRandomnessCommitment.fill(0);
                actionRandomness.canonicalEnvelope.fill(0);
                actionRandomness.envelopeHash.fill(0);
                actionRandomness.localRecordIdentifier.fill(0);
            }
            for (const record of witnessStateRecords) {
                record.canonicalEnvelope.fill(0);
                record.envelopeHash.fill(0);
                record.localRecordIdentifier.fill(0);
                record.authorizedEmptyPlaintext.fill(0);
                record.stateKey.fill(0);
            }
            throw error;
        } finally {
            destroyBrowserFoundationInitializationInput(copiedInput);
        }
    }

    #deriveBrowserFoundationInitializationRecords(
        input: WorkerBrowserFoundationInitializationPreparationInput,
    ): WorkerDerivedBrowserFoundationInitializationRecords {
        const activeLease = this.#requireActiveLease();
        const copiedInput = copyBrowserFoundationInitializationInput(input);
        const witnessStateRecords: Array<
            WorkerDerivedBrowserFoundationInitializationRecords['witnessStateRecords'][number]
        > = [];
        let actionRandomnessLocalRecordIdentifier:
            | Uint8Array<ArrayBuffer>
            | undefined;
        try {
            const subjectIdentityKeys = new Set<string>();
            actionRandomnessLocalRecordIdentifier =
                this.#deriveLocalRecordIdentifier({
                    recordType: 'actionRandomness',
                });
            for (const [
                roleIndex,
                witnessBinding,
            ] of copiedInput.orderedWitnessBindings.entries()) {
                if (
                    !byteArraysEqual(
                        witnessBinding.witnessParticipantIdentity,
                        activeLease.binding.participantId,
                    ) ||
                    byteArraysEqual(
                        witnessBinding.subjectParticipantIdentity,
                        activeLease.binding.participantId,
                    )
                ) {
                    throw new BrowserActionStorageCustodyError(
                        'InvalidInput',
                        `Witness recovery binding ${String(roleIndex)} is not a fixed-roster role owned by the local participant.`,
                    );
                }
                const subjectIdentityKey = bytesToHex(
                    witnessBinding.subjectParticipantIdentity,
                );
                if (subjectIdentityKeys.has(subjectIdentityKey)) {
                    throw new BrowserActionStorageCustodyError(
                        'Conflict',
                        'Witness recovery bindings contain a repeated subject participant.',
                    );
                }
                subjectIdentityKeys.add(subjectIdentityKey);
                const canonicalRole = encodeFoundationWitnessRole({
                    binding: activeLease.binding,
                    roleIndex,
                    runtimeBuildManifestHash:
                        copiedInput.runtimeBuildManifestHash,
                    witnessBinding,
                });
                const stateKey = domainSeparatedHash(
                    foundationWitnessStateKeyDomain,
                    canonicalRole,
                    'Witness state key',
                );
                const authorizedEmptyPlaintext =
                    encodeFoundationWitnessAuthorizedEmpty(canonicalRole);
                const localRecordIdentifier = this.#deriveLocalRecordIdentifier(
                    {
                        recordType: 'witnessState',
                        stateKey,
                    },
                );
                try {
                    witnessStateRecords.push(
                        Object.freeze({
                            authorizedEmptyPlaintext:
                                authorizedEmptyPlaintext.slice(),
                            localRecordIdentifier,
                            roleIndex,
                            stateKey: stateKey.slice(),
                        }),
                    );
                } catch (error) {
                    localRecordIdentifier.fill(0);
                    throw error;
                } finally {
                    authorizedEmptyPlaintext.fill(0);
                    stateKey.fill(0);
                    canonicalRole.fill(0);
                }
            }
            const retainedActionRandomnessLocalRecordIdentifier =
                actionRandomnessLocalRecordIdentifier;
            actionRandomnessLocalRecordIdentifier = undefined;
            return Object.freeze({
                actionRandomnessLocalRecordIdentifier:
                    retainedActionRandomnessLocalRecordIdentifier,
                witnessStateRecords: Object.freeze(witnessStateRecords),
            });
        } catch (error) {
            actionRandomnessLocalRecordIdentifier?.fill(0);
            for (const record of witnessStateRecords) {
                record.authorizedEmptyPlaintext.fill(0);
                record.localRecordIdentifier.fill(0);
                record.stateKey.fill(0);
            }
            throw error;
        } finally {
            destroyBrowserFoundationInitializationInput(copiedInput);
        }
    }

    async #createAndStage(
        binding: BrowserActionStorageRootBinding,
    ): Promise<WorkerPreparedDeviceWrappingState> {
        this.#assertNoStagedLease();
        const capability = this.#randomBytes(
            capabilityByteLength,
            'storage-root capability',
        );
        if (capability.every((byte) => byte === 0)) {
            capability.fill(0);
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                'Secure randomness returned an invalid storage-root capability.',
            );
        }
        const root = this.#randomBytes(
            actionStorageRootByteLength,
            'action storage root',
        );
        let stageOutput: Uint8Array<ArrayBuffer> | undefined;
        try {
            stageOutput = this.#runCommand(
                localStorageRootCommands.stageNew,
                concatenateBytes(capability, encodeBinding(binding), root),
                'stage a new local storage root',
                'runtime',
            );
            const staged = this.#readStageOutput(
                stageOutput,
                capability,
                binding,
            );
            this.#stagedLease = staged.lease;
            this.#stagedRootAllowsActionRandomnessMint = true;
            try {
                const wrapped = await this.#wrapStagedRoot();

                return Object.freeze({
                    ...wrapped,
                    storageRootCommitment: staged.commitment,
                });
            } catch (error) {
                return this.#discardAfterFailure(error);
            }
        } finally {
            root.fill(0);
            stageOutput?.fill(0);
            if (this.#stagedLease?.capability !== capability) {
                capability.fill(0);
            }
        }
    }

    async #stageDeviceWrappingOpen(input: {
        binding: BrowserActionStorageRootBinding;
        untrustedExpectedCommitment: UntrustedExpectedStorageRootCommitment;
        state: WorkerPreparedDeviceWrappingState;
    }): Promise<void> {
        const expectedCommitment = untrustedExpectedCommitmentBytes(
            input.untrustedExpectedCommitment,
        );
        const storedCommitment = copyExactBytes(
            input.state.storageRootCommitment,
            foundationHashByteLength,
            'Stored storage-root commitment',
        );
        if (!byteArraysEqual(storedCommitment, expectedCommitment)) {
            throw new BrowserActionStorageCustodyError(
                'CommitmentMismatch',
                'The stored storage-root commitment does not match the untrusted expected commitment.',
            );
        }
        this.#assertCompatibleStagedCommitment(expectedCommitment);
        const wrappedStorageRoot = input.state.wrappedStorageRoot;
        if (
            !(wrappedStorageRoot instanceof Uint8Array) ||
            wrappedStorageRoot.byteLength === 0 ||
            wrappedStorageRoot.byteLength > maximumWrappedStorageRootByteLength
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidCanonicalMaterial',
                'The device-wrapped storage-root envelope has an invalid length.',
            );
        }
        const decoded = this.#decodeDeviceEnvelope(
            input.binding,
            expectedCommitment,
            wrappedStorageRoot,
        );
        const combinedCiphertext = concatenateBytes(
            decoded.ciphertext,
            decoded.tag,
        );
        let openedRoot: Uint8Array<ArrayBuffer> | undefined;
        let capability: Uint8Array<ArrayBuffer> | undefined;
        let stageOutput: Uint8Array<ArrayBuffer> | undefined;
        try {
            try {
                openedRoot = new Uint8Array(
                    await this.#cryptoProvider.subtle.decrypt(
                        {
                            additionalData: arrayBufferFromBytes(
                                decoded.canonicalAssociatedData,
                            ),
                            iv: arrayBufferFromBytes(decoded.nonce),
                            name: 'AES-GCM',
                            tagLength: deviceWrappingTagByteLength * 8,
                        },
                        input.state.deviceKey,
                        arrayBufferFromBytes(combinedCiphertext),
                    ),
                );
            } catch (error) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidCanonicalMaterial',
                    'The device-wrapped storage root could not be authenticated and opened.',
                    error,
                );
            }
            if (openedRoot.byteLength !== actionStorageRootByteLength) {
                throw new BrowserActionStorageCustodyError(
                    'InvalidCanonicalMaterial',
                    `The opened action storage root must contain exactly ${actionStorageRootByteLength} bytes.`,
                );
            }
            const alreadyStagedLease = this.#stagedLease;
            if (alreadyStagedLease !== undefined) {
                const alreadyStagedRoot = this.#runCommand(
                    localStorageRootCommands.copyForDeviceWrap,
                    this.#leaseCommandInput(alreadyStagedLease),
                    'copy an already-staged root for authenticated comparison',
                    'runtime',
                );
                try {
                    if (!byteArraysEqual(alreadyStagedRoot, openedRoot)) {
                        throw new BrowserActionStorageCustodyError(
                            'CommitmentMismatch',
                            'The authenticated device-wrapped storage root does not match the root already staged in this worker.',
                        );
                    }

                    return;
                } finally {
                    alreadyStagedRoot.fill(0);
                }
            }
            this.#discardStaged();
            capability = this.#randomCapability();
            stageOutput = this.#runCommand(
                localStorageRootCommands.stageOpened,
                concatenateBytes(
                    capability,
                    encodeBinding(input.binding),
                    expectedCommitment,
                    openedRoot,
                ),
                'stage an opened local storage root',
                'open',
            );
            const staged = this.#readStageOutput(
                stageOutput,
                capability,
                input.binding,
            );
            if (!byteArraysEqual(staged.commitment, expectedCommitment)) {
                throw new BrowserActionStorageCustodyError(
                    'CommitmentMismatch',
                    'The opened storage root does not match the expected commitment.',
                );
            }
            this.#stagedLease = staged.lease;
            this.#stagedRootAllowsActionRandomnessMint = false;
        } finally {
            combinedCiphertext.fill(0);
            decoded.canonicalAssociatedData.fill(0);
            decoded.ciphertext.fill(0);
            decoded.nonce.fill(0);
            decoded.tag.fill(0);
            openedRoot?.fill(0);
            stageOutput?.fill(0);
            if (
                capability !== undefined &&
                this.#stagedLease?.capability !== capability
            ) {
                capability.fill(0);
            }
        }
    }

    #commitStaged(): void {
        const stagedLease = this.#requireStagedLease();
        this.#runCommand(
            localStorageRootCommands.commit,
            this.#leaseCommandInput(stagedLease),
            'commit a staged local storage root',
            'runtime',
        );
        this.#closeAllActionRandomness();
        this.#closeAllAuthenticatedRepairProtectionSessions();
        this.#closeAllStateVerifierSessions();
        this.#activeLease?.capability.fill(0);
        this.#activeLease = stagedLease;
        this.#stagedLease = undefined;
        this.#actionRandomnessRootMintConsumed =
            !this.#stagedRootAllowsActionRandomnessMint;
        this.#actionRandomnessSessionAcquisitionConsumed = false;
        this.#stagedRootAllowsActionRandomnessMint = false;
    }

    #discardStaged(): void {
        const stagedLease = this.#stagedLease;
        if (stagedLease === undefined) {
            return;
        }
        this.#runCommand(
            localStorageRootCommands.discard,
            this.#leaseCommandInput(stagedLease),
            'discard a staged local storage root',
            'runtime',
        );
        stagedLease.capability.fill(0);
        this.#stagedLease = undefined;
        this.#stagedRootAllowsActionRandomnessMint = false;
    }

    #destroyActive(): void {
        const activeLease = this.#activeLease;
        if (activeLease === undefined) {
            return;
        }
        this.#closeAllActionRandomness();
        this.#closeAllAuthenticatedRepairProtectionSessions();
        this.#closeAllStateVerifierSessions();
        this.#runCommand(
            localStorageRootCommands.destroy,
            this.#leaseCommandInput(activeLease),
            'destroy an active local storage root',
            'runtime',
        );
        activeLease.capability.fill(0);
        this.#activeLease = undefined;
        this.#actionRandomnessRootMintConsumed = true;
        this.#actionRandomnessSessionAcquisitionConsumed = true;
    }

    async #wrapStagedRoot(): Promise<WorkerPreparedDeviceWrappingState> {
        const stagedLease = this.#requireStagedLease();
        const canonicalAssociatedData = this.#runCommand(
            localStorageRootCommands.associatedData,
            this.#leaseCommandInput(stagedLease),
            'derive device-wrapping associated data',
            'runtime',
        );
        const root = this.#runCommand(
            localStorageRootCommands.copyForDeviceWrap,
            this.#leaseCommandInput(stagedLease),
            'copy a staged root for device wrapping',
            'runtime',
        );
        let combinedCiphertext: Uint8Array<ArrayBuffer> | undefined;
        try {
            if (root.byteLength !== actionStorageRootByteLength) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM registry returned a malformed action storage root.',
                );
            }
            const generatedKey = await this.#cryptoProvider.subtle.generateKey(
                { length: 256, name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt'],
            );
            if ('privateKey' in generatedKey) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'WebCrypto returned a key pair for AES-GCM.',
                );
            }
            const nonce = this.#randomBytes(
                deviceWrappingNonceByteLength,
                'device-wrapping nonce',
            );
            combinedCiphertext = new Uint8Array(
                await this.#cryptoProvider.subtle.encrypt(
                    {
                        additionalData: arrayBufferFromBytes(
                            canonicalAssociatedData,
                        ),
                        iv: arrayBufferFromBytes(nonce),
                        name: 'AES-GCM',
                        tagLength: deviceWrappingTagByteLength * 8,
                    },
                    generatedKey,
                    arrayBufferFromBytes(root),
                ),
            );
            if (
                combinedCiphertext.byteLength !==
                actionStorageRootByteLength + deviceWrappingTagByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'WebCrypto returned a malformed device-wrapping ciphertext.',
                );
            }
            const wrappedStorageRoot = this.#runCommand(
                localStorageRootCommands.encodeDeviceEnvelope,
                this.#leaseCommandInput(
                    stagedLease,
                    nonce,
                    combinedCiphertext.subarray(0, actionStorageRootByteLength),
                    combinedCiphertext.subarray(actionStorageRootByteLength),
                ),
                'encode a device-wrapped storage-root envelope',
                'runtime',
            );
            if (
                wrappedStorageRoot.byteLength === 0 ||
                wrappedStorageRoot.byteLength >
                    maximumWrappedStorageRootByteLength
            ) {
                wrappedStorageRoot.fill(0);
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM registry returned a malformed device-wrapped envelope.',
                );
            }

            return Object.freeze({
                deviceKey: generatedKey,
                storageRootCommitment: new Uint8Array(0),
                wrappedStorageRoot,
            });
        } finally {
            canonicalAssociatedData.fill(0);
            root.fill(0);
            combinedCiphertext?.fill(0);
        }
    }

    #decodeDeviceEnvelope(
        binding: BrowserActionStorageRootBinding,
        expectedCommitment: Uint8Array,
        wrappedStorageRoot: Uint8Array,
    ): DecodedDeviceEnvelope {
        const output = this.#runCommand(
            localStorageRootCommands.decodeDeviceEnvelope,
            concatenateBytes(
                encodeBinding(binding),
                expectedCommitment,
                wrappedStorageRoot,
            ),
            'decode a device-wrapped storage-root envelope',
            'open',
        );
        try {
            const associatedDataByteLength = decodeUnsigned32(output, 0);
            const fixedTrailingByteLength =
                deviceWrappingNonceByteLength +
                actionStorageRootByteLength +
                deviceWrappingTagByteLength;
            if (
                associatedDataByteLength === 0 ||
                output.byteLength !==
                    wasm32WordByteLength +
                        associatedDataByteLength +
                        fixedTrailingByteLength
            ) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM envelope decoder returned malformed output.',
                );
            }
            let offset = wasm32WordByteLength;
            const canonicalAssociatedData = output.slice(
                offset,
                (offset += associatedDataByteLength),
            );
            const nonce = output.slice(
                offset,
                (offset += deviceWrappingNonceByteLength),
            );
            const ciphertext = output.slice(
                offset,
                (offset += actionStorageRootByteLength),
            );
            const tag = output.slice(
                offset,
                (offset += deviceWrappingTagByteLength),
            );
            if (offset !== output.byteLength) {
                throw new BrowserActionStorageCustodyError(
                    'OwnedWorkerFailure',
                    'The WASM envelope decoder returned trailing bytes.',
                );
            }

            return Object.freeze({
                canonicalAssociatedData,
                ciphertext,
                nonce,
                tag,
            });
        } finally {
            output.fill(0);
        }
    }

    #readStageOutput(
        output: Uint8Array,
        capability: Uint8Array<ArrayBuffer>,
        binding: BrowserActionStorageRootBinding,
    ): Readonly<{
        commitment: Uint8Array<ArrayBuffer>;
        lease: RootLease;
    }> {
        if (output.byteLength !== handleByteLength + foundationHashByteLength) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The WASM storage-root stage command returned malformed output.',
            );
        }
        const handle = decodeUnsigned32(output, 0);
        if (handle === 0) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The WASM storage-root stage command returned a zero handle.',
            );
        }

        const commitment = output.slice(handleByteLength);

        return Object.freeze({
            commitment,
            lease: {
                binding: copyBinding(binding),
                capability,
                handle,
                storageRootCommitment: commitment.slice(),
            },
        });
    }

    #runActionRandomnessCommand(
        command: number,
        input: Uint8Array<ArrayBuffer>,
        operationName: string,
        failureContext: CommandFailureContext,
    ): Uint8Array<ArrayBuffer> {
        if (input.byteLength > maximumCommandByteLength) {
            input.fill(0);
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The action-randomness command input exceeds its supported byte limit.',
            );
        }
        const context = this.#actionRandomnessContext;
        return context.runExclusive(
            `action randomness: ${operationName}`,
            () => {
                let inputPointer = 0;
                let metadataPointer = 0;
                let outputPointer = 0;
                let outputByteLength = 0;
                try {
                    if (input.byteLength > 0) {
                        inputPointer = context.allocate(input.byteLength);
                        if (inputPointer === 0) {
                            throw new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'WASM could not allocate action-randomness input.',
                            );
                        }
                        new Uint8Array(
                            context.memory.buffer,
                            inputPointer,
                            input.byteLength,
                        ).set(input);
                    }
                    metadataPointer = context.allocate(
                        wasm32WordByteLength * 2,
                    );
                    if (metadataPointer === 0) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'WASM could not allocate action-randomness metadata.',
                        );
                    }
                    outputPointer = context.command(
                        command,
                        inputPointer,
                        input.byteLength,
                        metadataPointer,
                        metadataPointer + wasm32WordByteLength,
                    );
                    const metadata = new DataView(
                        context.memory.buffer,
                        metadataPointer,
                        wasm32WordByteLength * 2,
                    );
                    const status = metadata.getUint32(0, true);
                    outputByteLength = metadata.getUint32(
                        wasm32WordByteLength,
                        true,
                    );
                    if (status !== 0) {
                        if (outputPointer !== 0 || outputByteLength !== 0) {
                            throw new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'The WASM action-randomness command returned output with an error status.',
                            );
                        }
                        this.#throwCommandStatus(status, failureContext);
                    }
                    if (
                        outputByteLength >
                            actionRandomnessCommandOutputByteLimit(command) ||
                        (outputByteLength === 0) !== (outputPointer === 0) ||
                        outputPointer + outputByteLength >
                            context.memory.buffer.byteLength
                    ) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'The WASM action-randomness command returned invalid output metadata.',
                        );
                    }
                    return outputByteLength === 0
                        ? new Uint8Array(0)
                        : new Uint8Array(
                              context.memory.buffer,
                              outputPointer,
                              outputByteLength,
                          ).slice();
                } catch (error) {
                    throw error instanceof BrowserActionStorageCustodyError
                        ? error
                        : new BrowserActionStorageCustodyError(
                              'OwnedWorkerFailure',
                              `The WASM kernel failed to ${operationName}.`,
                              error,
                          );
                } finally {
                    input.fill(0);
                    if (outputPointer !== 0 && outputByteLength > 0) {
                        new Uint8Array(
                            context.memory.buffer,
                            outputPointer,
                            outputByteLength,
                        ).fill(0);
                        context.deallocate(outputPointer, outputByteLength);
                    }
                    if (metadataPointer !== 0) {
                        new Uint8Array(
                            context.memory.buffer,
                            metadataPointer,
                            wasm32WordByteLength * 2,
                        ).fill(0);
                        context.deallocate(
                            metadataPointer,
                            wasm32WordByteLength * 2,
                        );
                    }
                    if (inputPointer !== 0) {
                        new Uint8Array(
                            context.memory.buffer,
                            inputPointer,
                            input.byteLength,
                        ).fill(0);
                        context.deallocate(inputPointer, input.byteLength);
                    }
                }
            },
        );
    }

    #runCommand(
        command: number,
        input: Uint8Array<ArrayBuffer>,
        operationName: string,
        failureContext: CommandFailureContext,
    ): Uint8Array<ArrayBuffer> {
        if (input.byteLength > maximumCommandByteLength) {
            input.fill(0);
            throw new BrowserActionStorageCustodyError(
                'InvalidInput',
                'The local storage-root command input exceeds its supported byte limit.',
            );
        }

        return this.#context.runExclusive(
            `local storage root: ${operationName}`,
            () => {
                let inputPointer = 0;
                let metadataPointer = 0;
                let outputPointer = 0;
                let outputByteLength = 0;
                try {
                    if (input.byteLength > 0) {
                        inputPointer = this.#context.allocate(input.byteLength);
                        if (inputPointer === 0) {
                            throw new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'WASM could not allocate local storage-root input.',
                            );
                        }
                        new Uint8Array(
                            this.#context.memory.buffer,
                            inputPointer,
                            input.byteLength,
                        ).set(input);
                    }
                    metadataPointer = this.#context.allocate(
                        wasm32WordByteLength * 2,
                    );
                    if (metadataPointer === 0) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'WASM could not allocate local storage-root metadata.',
                        );
                    }
                    outputPointer = this.#context.command(
                        command,
                        inputPointer,
                        input.byteLength,
                        metadataPointer,
                        metadataPointer + wasm32WordByteLength,
                    );
                    const metadata = new Uint32Array(
                        this.#context.memory.buffer,
                        metadataPointer,
                        2,
                    );
                    const status = metadata[0];
                    outputByteLength = metadata[1];
                    if (status !== 0) {
                        if (outputPointer !== 0 || outputByteLength !== 0) {
                            throw new BrowserActionStorageCustodyError(
                                'OwnedWorkerFailure',
                                'The WASM local storage-root command returned output with an error status.',
                            );
                        }
                        this.#throwCommandStatus(status, failureContext);
                    }
                    if (
                        outputByteLength > maximumCommandByteLength ||
                        (outputByteLength === 0) !== (outputPointer === 0)
                    ) {
                        throw new BrowserActionStorageCustodyError(
                            'OwnedWorkerFailure',
                            'The WASM local storage-root command returned invalid output metadata.',
                        );
                    }
                    if (outputByteLength === 0) {
                        return new Uint8Array(0);
                    }

                    return new Uint8Array(
                        this.#context.memory.buffer,
                        outputPointer,
                        outputByteLength,
                    ).slice();
                } catch (error) {
                    throw error instanceof BrowserActionStorageCustodyError
                        ? error
                        : new BrowserActionStorageCustodyError(
                              'OwnedWorkerFailure',
                              `The WASM kernel failed to ${operationName}.`,
                              error,
                          );
                } finally {
                    input.fill(0);
                    if (outputPointer !== 0 && outputByteLength > 0) {
                        this.#context.deallocate(
                            outputPointer,
                            outputByteLength,
                        );
                    }
                    if (metadataPointer !== 0) {
                        this.#context.deallocate(
                            metadataPointer,
                            wasm32WordByteLength * 2,
                        );
                    }
                    if (inputPointer !== 0) {
                        this.#context.deallocate(
                            inputPointer,
                            input.byteLength,
                        );
                    }
                }
            },
        );
    }

    #throwCommandStatus(
        status: number,
        failureContext: CommandFailureContext,
    ): never {
        if (
            failureContext === 'recordOpen' &&
            (status === localStorageRootStatuses.wrongContext ||
                status === localStorageRootStatuses.wrongHashOrRoot ||
                status === localStorageRootStatuses.malformedEncoding ||
                status === localStorageRootStatuses.unsupportedVersionOrSuite ||
                status === localStorageRootStatuses.wrongTypeOrLength)
        ) {
            throw new BrowserActionStorageCustodyError(
                'RecordAuthenticationFailed',
                'The local record could not be authenticated for its expected context.',
            );
        }
        if (
            status === localStorageRootStatuses.wrongContext ||
            status === localStorageRootStatuses.wrongHashOrRoot
        ) {
            throw new BrowserActionStorageCustodyError(
                'CommitmentMismatch',
                'The local storage-root material does not match its required binding or commitment.',
            );
        }
        if (status === localStorageRootStatuses.consumedState) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The local storage-root operation refers to consumed or replaced state.',
            );
        }
        if (
            status === localStorageRootStatuses.malformedEncoding ||
            status === localStorageRootStatuses.unsupportedVersionOrSuite ||
            status === localStorageRootStatuses.wrongTypeOrLength
        ) {
            throw new BrowserActionStorageCustodyError(
                failureContext === 'runtime'
                    ? 'OwnedWorkerFailure'
                    : 'InvalidCanonicalMaterial',
                'The local storage-root command refused malformed canonical material.',
            );
        }
        if (status === localStorageRootStatuses.outsideSupportedProfile) {
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                'The local storage-root material exceeds the absolute runtime safety bound.',
            );
        }
        if (
            status === localStorageRootStatuses.resourceLimit ||
            status === localStorageRootStatuses.staleHandle
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'The local storage-root registry refused an unavailable lease.',
            );
        }
        if (status === localStorageRootStatuses.capabilityMismatch) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The local storage-root registry refused its opaque capability.',
            );
        }

        throw new BrowserActionStorageCustodyError(
            'OwnedWorkerFailure',
            `The local storage-root command returned unknown status ${status}.`,
        );
    }

    #leaseCommandInput(
        lease: RootLease,
        ...trailingValues: readonly Uint8Array[]
    ): Uint8Array<ArrayBuffer> {
        return concatenateBytes(
            encodeUnsigned32(lease.handle),
            lease.capability,
            ...trailingValues,
        );
    }

    #randomCapability(): Uint8Array<ArrayBuffer> {
        const capability = this.#randomBytes(
            capabilityByteLength,
            'storage-root capability',
        );
        if (capability.every((byte) => byte === 0)) {
            capability.fill(0);
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                'Secure randomness returned an invalid storage-root capability.',
            );
        }

        return capability;
    }

    #randomBytes(byteLength: number, label: string): Uint8Array<ArrayBuffer> {
        const bytes = new Uint8Array(byteLength);
        try {
            this.#cryptoProvider.getRandomValues(bytes);
        } catch (error) {
            bytes.fill(0);
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                `Secure randomness is unavailable for the ${label}.`,
                error,
            );
        }

        return bytes;
    }

    #assertNoStagedLease(): void {
        if (this.#stagedLease !== undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A local storage root is already staged in this worker.',
            );
        }
    }

    #assertCompatibleStagedCommitment(expectedCommitment: Uint8Array): void {
        if (
            this.#stagedLease !== undefined &&
            !byteArraysEqual(
                this.#stagedLease.storageRootCommitment,
                expectedCommitment,
            )
        ) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'A different local storage root is already staged in this worker.',
            );
        }
    }

    #requireStagedLease(): RootLease {
        if (this.#stagedLease === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'No local storage root is staged in this worker.',
            );
        }

        return this.#stagedLease;
    }

    #requireActiveLease(): RootLease {
        if (this.#activeLease === undefined) {
            throw new BrowserActionStorageCustodyError(
                'InvalidState',
                'No local storage root is active in this worker.',
            );
        }

        return this.#activeLease;
    }

    #commonProofStorageRootAccess(activeLease: RootLease): Readonly<{
        context: NonNullable<
            ReturnType<typeof resolveCommonProofKernelContext>
        >;
        storageRootCapability: Uint8Array;
        storageRootHandle: number;
    }> {
        const context = resolveCommonProofKernelContext(this.#kernel);
        if (context === undefined) {
            throw new BrowserActionStorageCustodyError(
                'Unavailable',
                'The loaded WASM kernel does not expose the common-proof worker runtime.',
            );
        }
        return Object.freeze({
            context,
            storageRootCapability: activeLease.capability,
            storageRootHandle: activeLease.handle,
        });
    }

    #discardAfterFailure(originalFailure: unknown): never {
        try {
            this.#discardStaged();
        } catch (cleanupFailure) {
            throw new BrowserActionStorageCustodyError(
                'OwnedWorkerFailure',
                'The local storage-root operation failed and staged-root cleanup also failed.',
                [originalFailure, cleanupFailure],
            );
        }

        throw originalFailure;
    }

    #enqueue<Result>(
        operation: () => Promise<Result> | Result,
    ): Promise<Result> {
        const result = this.#operationTail.then(operation, operation);
        this.#operationTail = result.then(
            () => undefined,
            () => undefined,
        );

        return result;
    }
}
