import {
    BrowserActionStorageCustodyError,
    foundationProfile,
    stateCapabilityKinds,
} from '@sealed-lattice/types';
import { expect } from 'vitest';

import {
    openClosedWorkerCommonProofGenerationFamilyAdapter,
    releaseClosedWorkerCommonProofGenerationFamilyAdapter,
    type ClosedWorkerCommonProofGenerationFamilyAdapter,
} from '../../../src/common-proof-worker-runtime.js';
import {
    createWasmBrowserActionStorageWorkerKernel,
    loadFreshTranscriptCoreKernel,
    type RuntimeBuildManifest,
} from '../../../src/index.js';
import {
    openStateVerifierSession,
    type StateVerifierSession,
    type VerifiedStateDurableBinding,
} from '../../../src/state-verifier-runtime.js';
import { registerCommonProofKernelContext } from '../../../src/transcript-core-bridge/common-proof-kernel-context.js';
import type { TranscriptCoreKernelCommandRuntime } from '../../../src/transcript-core-bridge/kernel-runtime.js';
import type { TranscriptCoreKernel } from '../../../src/transcript-core-bridge/kernel-types.js';

import {
    createMockKernelRuntime,
    createResetSafeCommonProofCursorManifest,
    createVerifiedApplicationFixture,
    memoryBytes,
    noSecondPollValue,
    writeGenerationPoll,
    writeUnsigned32,
} from './kernel-fixtures.js';
import {
    cryptoProvider,
    encodeRequest,
    hashByteLength,
    installedCommonProofVerificationBindingHash,
    installedProofAttemptLineageIdentifier,
    runtimeBinding,
} from './wire-fixtures.js';

import {
    createCanonicalCarrierSigningKeyPairFixtures,
    signCanonicalCarrierFixtureMessage,
} from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';
import {
    openAuthenticatedCheckpointStore,
    type AuthenticatedCheckpointPhysicalAccountingScope,
} from '#packages/protocol/src/runtime/authenticated-checkpoint-store';
import type {
    BrowserActionStorageCustody,
    BrowserActionStorageRootBinding,
    BrowserFoundationFreshnessCoordinate,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import {
    closeCommonProofExecutionEnvironmentInInstalledCustodyWorker,
    copyReservedCommonProofCheckpointLineageIdentifier,
    installBrowserActionStorageCustodyWorkerHost,
    openCommonProofExecutionEnvironmentInInstalledCustodyWorker,
    prepareCommonProofGenerationInInstalledCustodyWorker,
    releaseReservedCommonProofCheckpointLineageInInstalledCustodyWorker,
    reserveCommonProofCheckpointLineageInInstalledCustodyWorker,
    runCommonProofGenerationInInstalledCustodyWorker,
    suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker,
    type BrowserActionStorageCustodyWorkerConfiguration,
    type InstalledCommonProofCheckpointLineageReservation,
} from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';
import type { BrowserFoundationInitializationInput } from '#packages/protocol/src/runtime/browser-foundation-operation-owner';
import {
    commonProofApplicationHandoffLogicalRecordKey,
    deriveCommonProofAttemptLogicalRecordPrefix,
    openCommonProofBrowserCustody,
    type CommonProofBrowserCustody,
} from '#packages/protocol/src/runtime/common-proof-browser-custody';
import { checkpointStateStreamDomain } from '#packages/protocol/src/runtime/common-proof-browser-custody/records';
import {
    openDurableStateWitnessService,
    type DurableStateWitnessServiceLimits,
} from '#packages/protocol/src/runtime/durable-state-witness-service';
import { createRuntimeBuildCheckpointBoundaryPolicy } from '#packages/protocol/src/runtime/runtime-build-checkpoint-boundary-policy';
import type {
    WebLockCommittedBrowserFoundationInitialization,
    WebLockFoundationWitnessRecord,
    WebLockOwnedBrowserActionStorageCustody,
    WebLockOwnedFoundationWitnessRole,
} from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import { commonProofStorageCapacityProfile } from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import {
    generateRuntimeStorageEncryptionKey,
    openRuntimeTestStore,
    runtimeAuthorityContext,
} from '#packages/protocol/tests/support/runtime-storage-test-support';
import {
    asciiItem,
    canonicalItem,
    canonicalTuple,
    concatenateBytes,
    foundationHash512,
    hashItem,
    unsigned16LittleEndian,
    unsigned32LittleEndian,
    unsigned64Item,
    variableBytesItem,
} from '#packages/wasm/tests/canonical-tuple-test-helpers';
import { createStateVerifierTestVector } from '#packages/wasm/tests/state-verifier-test-vectors';

type InstalledCustodyCommonProofExecutionEnvironment = Awaited<
    ReturnType<
        typeof openCommonProofExecutionEnvironmentInInstalledCustodyWorker
    >
>;

const installedCommonProofGenerationBindingHash = runtimeBinding(0x5b);

export const createCommonProofGenerationCursorFixtureBytes = (
    _kernel?: TranscriptCoreKernel,
): Uint8Array<ArrayBuffer> =>
    createResetSafeCommonProofCursorManifest(
        installedProofAttemptLineageIdentifier,
        installedCommonProofGenerationBindingHash,
    );

export const commonProofApplicationStatementSchemaIdentifier = 0x1217;

const foundationWitnessServiceLimits: DurableStateWitnessServiceLimits =
    Object.freeze({
        maximumExactOutputByteLength: 65_536,
        maximumRecordSealingCount: 128,
        maximumSignedVoteCarrierByteLength: 65_536,
        transactionLifetimeMilliseconds: 10_000,
    });

const foundationStorageTransactionLimits = Object.freeze({
    maximumActiveTransactionCount: 2,
    maximumLeaseByteLength:
        commonProofStorageCapacityProfile.maximumLeaseByteLength,
    maximumLeaseCountPerTransaction:
        commonProofStorageCapacityProfile.maximumLeaseCountPerTransaction,
    maximumOwnedRecordCount:
        commonProofStorageCapacityProfile.maximumAdditionalOwnedRecordCount +
        256,
    maximumStoredValueByteLength:
        commonProofStorageCapacityProfile.maximumAdditionalStoredValueByteLength +
        commonProofStorageCapacityProfile.maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength +
        1_048_576,
    maximumTransactionByteLength:
        commonProofStorageCapacityProfile.maximumTransactionByteLength,
    maximumTransactionLifetimeMilliseconds: 10_000,
});

const commonProofCheckpointLimits = Object.freeze({
    maximumActiveOperationIdentityCount: 64,
    maximumCheckpointStateByteLength: 1_048_576,
    maximumManifestByteLength: 16_384,
    maximumRandomCursorManifestByteLength: 4_096,
    maximumRecordSealingCount: 256,
    maximumSourceDigestCount: 8,
    transactionLifetimeMilliseconds: 10_000,
});

const commonProofCheckpointStateSchemaIdentifier = 0x010c;
const commonProofRuntimeBuildManifest = Object.freeze({
    operationProfiles: Object.freeze([
        Object.freeze({
            operationKind: commonProofApplicationStatementSchemaIdentifier,
            safeBoundaries: Object.freeze([
                Object.freeze({
                    orderedRandomUses: Object.freeze([
                        Object.freeze({
                            family: commonProofApplicationStatementSchemaIdentifier,
                            purpose: 1,
                        }),
                    ]),
                    stateSchemaIdentifier:
                        commonProofCheckpointStateSchemaIdentifier,
                }),
            ]),
        }),
    ]),
    orderedAssets: Object.freeze([]),
    orderedSuiteArtifactPaths: Object.freeze([]),
    protocolVersion: 1,
    releaseIdentifier: 'common-proof-checkpoint-custody-test',
    suiteIdentifier: new Uint8Array(64),
    suiteRecordPath: '/suite.canonical',
}) satisfies RuntimeBuildManifest;
const commonProofCheckpointBoundaryPolicy =
    createRuntimeBuildCheckpointBoundaryPolicy({
        operationKind: commonProofApplicationStatementSchemaIdentifier,
        orderedBoundaryBindings: Object.freeze([
            Object.freeze({
                safeBoundaryOrdinal: 0,
                stateSchemaIdentifier:
                    commonProofCheckpointStateSchemaIdentifier,
                stateStreamDomain: checkpointStateStreamDomain,
            }),
        ]),
        runtimeBuildManifest: commonProofRuntimeBuildManifest,
    });
export const workerCheckpointStateBytes = Uint8Array.of(0x41);
const workerCheckpointChunkDigest = foundationHash512(
    'sealed-lattice/transport/chunk/v1',
    asciiItem(checkpointStateStreamDomain),
    canonicalItem(0x04, unsigned32LittleEndian(0)),
    canonicalItem(
        0x04,
        unsigned32LittleEndian(workerCheckpointStateBytes.byteLength),
    ),
    variableBytesItem(workerCheckpointStateBytes),
);
const workerCheckpointStreamDescriptor = canonicalTuple(
    0x1800,
    unsigned64Item(BigInt(workerCheckpointStateBytes.byteLength)),
    canonicalItem(
        0x0e,
        concatenateBytes(
            unsigned16LittleEndian(0x06),
            unsigned32LittleEndian(1),
            workerCheckpointChunkDigest,
        ),
    ),
    hashItem(
        foundationHash512(
            'sealed-lattice/transport/full-object/v1',
            asciiItem(checkpointStateStreamDomain),
            unsigned64Item(BigInt(workerCheckpointStateBytes.byteLength)),
            variableBytesItem(workerCheckpointStateBytes),
        ),
    ),
);

export const createWorkerCheckpointBoundary = () =>
    Object.freeze({
        operationKind: commonProofApplicationStatementSchemaIdentifier,
        orderedSourceDigests: Object.freeze([
            installedCommonProofGenerationBindingHash.slice(),
            installedCommonProofGenerationBindingHash.slice(),
            installedCommonProofVerificationBindingHash.slice(),
        ]),
        privateRandomCursorManifestBytes:
            createCommonProofGenerationCursorFixtureBytes(),
        privateRandomnessStreamAttemptIdentifier:
            installedProofAttemptLineageIdentifier.slice(),
        safeBoundaryOrdinal: 0,
        stateStreamDescriptorBytes: workerCheckpointStreamDescriptor.slice(),
        stateStreamDomain: checkpointStateStreamDomain,
    });

export const createExpectedWorkerCheckpointBoundary = () =>
    Object.freeze({
        operationKind: commonProofApplicationStatementSchemaIdentifier,
        orderedSourceDigests: Object.freeze([
            installedCommonProofGenerationBindingHash.slice(),
            installedCommonProofGenerationBindingHash.slice(),
            installedCommonProofVerificationBindingHash.slice(),
        ]),
        privateRandomCursorManifestBytes:
            createCommonProofGenerationCursorFixtureBytes(),
        privateRandomnessStreamAttemptIdentifier:
            installedProofAttemptLineageIdentifier.slice(),
        safeBoundaryOrdinal: 0,
        stateStreamDomain: checkpointStateStreamDomain,
    });

type SameRealmCustodyWorkerResponse = Readonly<{
    errorCode?: string;
    errorMessage?: string;
    messageKind: string;
    requestIdentifier?: number;
    result?: unknown;
}>;

class SameRealmCustodyWorkerScope {
    readonly #pendingResponses = new Map<
        number,
        Readonly<{
            reject(error: unknown): void;
            resolve(value: unknown): void;
        }>
    >();
    #listener: ((event: MessageEvent<unknown>) => void) | undefined;
    #nextRequestIdentifier = 1;
    public readonly terminalNotifications: SameRealmCustodyWorkerResponse[] =
        [];

    public addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void {
        if (type !== 'message' || this.#listener !== undefined) {
            throw new Error(
                'The same-realm custody worker listener was installed more than once.',
            );
        }
        this.#listener = listener;
    }

    public removeEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void {
        if (type !== 'message') {
            throw new Error(
                'The same-realm custody worker removed an unknown listener kind.',
            );
        }
        if (this.#listener === listener) {
            this.#listener = undefined;
        }
    }

    public postMessage(message: unknown): void {
        const response = message as SameRealmCustodyWorkerResponse;
        if (response.requestIdentifier === undefined) {
            this.terminalNotifications.push(response);
            const terminalFailure = Object.assign(
                new Error('The same-realm custody worker retired.'),
                { code: response.errorCode },
            );
            for (const pending of this.#pendingResponses.values()) {
                pending.reject(terminalFailure);
            }
            this.#pendingResponses.clear();
            return;
        }
        const pending = this.#pendingResponses.get(response.requestIdentifier);
        if (pending === undefined) {
            throw new Error(
                'The same-realm custody worker returned an unknown request identifier.',
            );
        }
        this.#pendingResponses.delete(response.requestIdentifier);
        if (
            response.messageKind === 'browser-action-storage-custody-completed'
        ) {
            pending.resolve(response.result);
            return;
        }
        const failure = new Error(
            response.errorMessage ??
                `The same-realm custody worker command failed with ${response.errorCode ?? 'an unclassified error'}.`,
        ) as Error & { code?: string };
        failure.code = response.errorCode;
        pending.reject(failure);
    }

    public dispatchMalformedRequest(data: unknown = undefined): void {
        const listener = this.#listener;
        if (listener === undefined) {
            throw new Error('The same-realm custody worker is not listening.');
        }
        listener({ data } as MessageEvent<unknown>);
    }

    public send(command: string, input: unknown): Promise<unknown> {
        const listener = this.#listener;
        if (listener === undefined) {
            return Promise.reject(
                new Error('The same-realm custody worker is not listening.'),
            );
        }
        const requestIdentifier = this.#nextRequestIdentifier;
        this.#nextRequestIdentifier += 1;
        return new Promise((resolve, reject) => {
            this.#pendingResponses.set(requestIdentifier, {
                reject,
                resolve,
            });
            listener({
                data: {
                    command,
                    input,
                    messageKind: 'browser-action-storage-custody-request',
                    requestIdentifier,
                },
            } as MessageEvent<unknown>);
        });
    }
}

const createFoundationStateDurableBinding = (
    kernel: TranscriptCoreKernel,
): Readonly<{
    binding: VerifiedStateDurableBinding;
    session: StateVerifierSession;
    stateVector: ReturnType<typeof createStateVerifierTestVector>;
}> => {
    const stateVector = createStateVerifierTestVector();
    const opened = openStateVerifierSession({
        configuration: {
            actionContextHash: stateVector.actionContextHash,
            canonicalRosterBytes: stateVector.canonicalRosterBytes,
            ceremonyContextHash: stateVector.ceremonyContextHash,
            suiteIdentifier: stateVector.suiteIdentifier,
        },
        kernel,
    });
    if (!opened.isValid) {
        throw new Error(opened.refusalReason);
    }
    const reservationIntent = opened.value.verifyReservationIntent({
        canonicalReservationIntentCarrier:
            stateVector.reservation.canonicalIntentCarrier,
        capabilityKind: stateCapabilityKinds.targetRelease,
        expectedAuthorizationHash: stateVector.authorizationHash,
        subjectParticipantIdentity: stateVector.subjectParticipantIdentity,
    });
    if (!reservationIntent.isValid) {
        opened.value.cancel();
        throw new Error(reservationIntent.refusalReason);
    }
    const durableBinding = opened.value.durableBindingFor(
        reservationIntent.value,
    );
    if (!durableBinding.isValid) {
        opened.value.cancel();
        throw new Error(durableBinding.refusalReason);
    }
    return Object.freeze({
        binding: durableBinding.value,
        session: opened.value,
        stateVector,
    });
};

export const openSameRealmCommonProofApplicationHost = async (input?: {
    additionalInitializationCommitGate?: Promise<void>;
    firstAdditionalInitializationWitnessCount?: number;
    decorateCommonProofCustody?: (
        custody: CommonProofBrowserCustody,
    ) => CommonProofBrowserCustody;
    failActionRandomnessCloseAttemptNumbers?: readonly number[];
    failFirstAdditionalActivationHeadComparison?: boolean;
    failFirstFoundationWitnessClose?: boolean;
    failFoundationWitnessCloseAttemptNumbers?: readonly number[];
    failFirstStateObjectRelease?: boolean;
    failVerifiedCapabilityReleaseAttempt?: number;
    onAdditionalInitializationCommitStarted?: () => void;
    proofBytes?: Uint8Array;
}): Promise<
    Readonly<{
        actionRandomnessHandleIdentifier: string;
        authenticatedFoundationHead(): Promise<BrowserFoundationFreshnessCoordinate>;
        activateFreshFoundationInitialization(batchIdentifier: string): Promise<
            Readonly<{
                actionRandomnessHandleIdentifier: string;
                orderedWitnessRoleHandleIdentifiers: readonly string[];
            }>
        >;
        close(): Promise<void>;
        commitAdditionalFoundationOperationInitialization(): Promise<string>;
        cleanupAttemptCounts(): Readonly<{
            actionRandomness: number;
            foundationWitness: number;
            stateObjectRelease: number;
        }>;
        fixture: Awaited<ReturnType<typeof createVerifiedApplicationFixture>>;
        installedHost: () => Promise<void>;
        kernel: TranscriptCoreKernel;
        ownedCustodyCloseCount(): number;
        retainAdditionalFoundationInitializationBatches(): Promise<void>;
        retainFoundationStateReservationIntent(): Promise<string>;
        storageAdapter: Awaited<
            ReturnType<typeof openRuntimeTestStore>
        >['adapter'];
        workerScope: SameRealmCustodyWorkerScope;
        witnessRoleIdentifier: string;
    }>
> => {
    const fixture = await createVerifiedApplicationFixture({
        failVerifiedCapabilityReleaseAttempt:
            input?.failVerifiedCapabilityReleaseAttempt,
        predecessorFreshnessSequence: 0n,
        proofBytes: input?.proofBytes,
    });
    const kernel = await loadFreshTranscriptCoreKernel();
    registerCommonProofKernelContext(kernel, fixture.runtime);
    const workerKernel = createWasmBrowserActionStorageWorkerKernel({ kernel });
    const stateAuthority = createFoundationStateDurableBinding(kernel);
    let stateAuthoritySessionCancelled = false;
    const cancelStateAuthoritySession = (): void => {
        if (stateAuthoritySessionCancelled) {
            return;
        }
        stateAuthority.session.cancel();
        stateAuthoritySessionCancelled = true;
    };
    const foundationSigningKeyPairs =
        createCanonicalCarrierSigningKeyPairFixtures(
            foundationProfile.participantCount,
        );
    const witnessSigningSecretKey =
        foundationSigningKeyPairs[1]?.secretKey.slice();
    for (const keyPair of foundationSigningKeyPairs) {
        keyPair.secretKey.fill(0);
    }
    if (witnessSigningSecretKey === undefined) {
        throw new Error('The foundation fixture has no witness signing key.');
    }
    const binding: BrowserActionStorageRootBinding = Object.freeze({
        actionContextHash: stateAuthority.stateVector.actionContextHash.slice(),
        ceremonyContextHash:
            stateAuthority.stateVector.ceremonyContextHash.slice(),
        participantId:
            stateAuthority.stateVector.witnessParticipantIdentity.slice(),
        suiteId: stateAuthority.stateVector.suiteIdentifier.slice(),
    });
    const preparedRoot = await workerKernel.createAndStageDeviceWrappingState({
        binding,
    });
    await workerKernel.commitStagedActionStorageRoot();
    preparedRoot.storageRootCommitment.fill(0);
    preparedRoot.wrappedStorageRoot.fill(0);
    const stateCleanupActionRandomness =
        input?.failFirstStateObjectRelease === true
            ? await workerKernel.createAndSealActionRandomness({
                  recordVersion: 0n,
              })
            : undefined;
    stateCleanupActionRandomness?.canonicalEnvelope.fill(0);
    const releaseActionStateObject: (identifier: string) => Promise<void> =
        workerKernel.releaseActionStateObject.bind(workerKernel);
    let stateObjectReleaseAttemptCount = 0;
    if (input?.failFirstStateObjectRelease === true) {
        Object.defineProperty(workerKernel, 'releaseActionStateObject', {
            configurable: true,
            value: async (identifier: string): Promise<void> => {
                stateObjectReleaseAttemptCount += 1;
                if (stateObjectReleaseAttemptCount === 1) {
                    throw new Error('Injected fail-once state-object release.');
                }
                await releaseActionStateObject(identifier);
            },
        });
    }

    const storage = await openRuntimeTestStore({
        limits: foundationStorageTransactionLimits,
        namespace: 'same-realm-common-proof-application-test',
    });
    const checkpointStorage = await openRuntimeTestStore({
        namespace: 'same-realm-common-proof-checkpoint-test',
    });
    const repairHeadLogicalRecordKey =
        'test/same-realm-common-proof-capacity-head';
    const repairHeadWriteTransaction = await storage.store.beginTransaction({
        lifetimeMilliseconds: 5_000,
    });
    try {
        const repairHeadWriteLease =
            await repairHeadWriteTransaction.issueWriteLease({
                declaredByteLength: 1,
                logicalRecordKey: repairHeadLogicalRecordKey,
            });
        await repairHeadWriteLease.write(Uint8Array.of(1));
        await repairHeadWriteLease.seal(() => undefined);
        await repairHeadWriteTransaction.commit();
    } catch (error) {
        await repairHeadWriteTransaction.closeAfterFailure();
        throw error;
    }
    const repairHeadDeleteTransaction = await storage.store.beginTransaction({
        lifetimeMilliseconds: 5_000,
    });
    try {
        await repairHeadDeleteTransaction.stageDeletion(
            repairHeadLogicalRecordKey,
        );
        await repairHeadDeleteTransaction.commit();
    } catch (error) {
        await repairHeadDeleteTransaction.closeAfterFailure();
        throw error;
    }
    const baselineAuthenticatedHead =
        await storage.store.authenticateCurrentHead();
    const baselineFreshnessSequence =
        baselineAuthenticatedHead.namespaceSequence;
    const baselineAuthenticatedHeadDigest =
        baselineAuthenticatedHead.authenticatedHeadDigest.slice();
    baselineAuthenticatedHead.authenticatedHeadDigest.fill(0);
    baselineAuthenticatedHead.storageInstanceIdentity.fill(0);
    const encryptionKey = await generateRuntimeStorageEncryptionKey();
    let transferableCheckpointStore:
        | ReturnType<typeof openAuthenticatedCheckpointStore>
        | undefined;
    const baselineFoundationCoordinate =
        (): BrowserFoundationFreshnessCoordinate =>
            Object.freeze({
                authenticatedHeadDigest: new Uint8Array(hashByteLength).fill(
                    0x51,
                ),
                freshnessSequence: 0n,
                storageInstanceIdentity: new Uint8Array(hashByteLength).fill(
                    0x61,
                ),
            });
    let openedFoundationWitnessRoleCount = 0;
    let injectedAdditionalActivationHeadConflict = false;
    const coordinateForCurrentStore =
        async (): Promise<BrowserFoundationFreshnessCoordinate> => {
            const authenticatedHead =
                await storage.store.authenticateCurrentHead();
            const freshnessSequence =
                authenticatedHead.namespaceSequence - baselineFreshnessSequence;
            const authenticatedHeadDigest =
                authenticatedHead.authenticatedHeadDigest.slice();
            for (
                let digestByteIndex = 0;
                digestByteIndex < authenticatedHeadDigest.byteLength;
                digestByteIndex += 1
            ) {
                authenticatedHeadDigest[digestByteIndex] ^=
                    baselineAuthenticatedHeadDigest[digestByteIndex] ^ 0x51;
            }
            authenticatedHead.authenticatedHeadDigest.fill(0);
            authenticatedHead.storageInstanceIdentity.fill(0);
            if (
                input?.failFirstAdditionalActivationHeadComparison === true &&
                !injectedAdditionalActivationHeadConflict &&
                openedFoundationWitnessRoleCount >=
                    2 * (foundationProfile.participantCount - 1)
            ) {
                authenticatedHeadDigest[0] ^= 0xff;
                injectedAdditionalActivationHeadConflict = true;
            }
            return Object.freeze({
                authenticatedHeadDigest,
                freshnessSequence,
                storageInstanceIdentity: new Uint8Array(hashByteLength).fill(
                    0x61,
                ),
            });
        };
    const witnessRecords: WebLockFoundationWitnessRecord[] = Array.from(
        { length: foundationProfile.participantCount - 1 },
        (_unused, witnessIndex) =>
            Object.freeze({
                actionRandomnessCommitment: new Uint8Array(64).fill(0x21),
                authorizedEmptyPlaintext: Uint8Array.of(0),
                localRecordIdentifier: new Uint8Array(64).fill(
                    0x31 + witnessIndex,
                ),
                roleIndex: witnessIndex,
                stateKey: new Uint8Array(64).fill(0x41 + witnessIndex),
                subjectParticipantIdentity:
                    witnessIndex === 0
                        ? stateAuthority.stateVector.subjectParticipantIdentity.slice()
                        : new Uint8Array(64).fill(0x61 + witnessIndex),
                witnessParticipantIdentity: binding.participantId.slice(),
            }),
    );
    const copyWitnessRecord = (
        record: WebLockFoundationWitnessRecord,
    ): WebLockFoundationWitnessRecord =>
        Object.freeze({
            actionRandomnessCommitment:
                record.actionRandomnessCommitment.slice(),
            authorizedEmptyPlaintext: record.authorizedEmptyPlaintext.slice(),
            localRecordIdentifier: record.localRecordIdentifier.slice(),
            roleIndex: record.roleIndex,
            stateKey: record.stateKey.slice(),
            subjectParticipantIdentity:
                record.subjectParticipantIdentity.slice(),
            witnessParticipantIdentity:
                record.witnessParticipantIdentity.slice(),
        });
    const byteArraysEqual = (left: Uint8Array, right: Uint8Array): boolean =>
        left.byteLength === right.byteLength &&
        left.every((byte, byteIndex) => byte === right[byteIndex]);
    const witnessRecordsEqual = (
        left: WebLockFoundationWitnessRecord,
        right: WebLockFoundationWitnessRecord,
    ): boolean =>
        left.roleIndex === right.roleIndex &&
        byteArraysEqual(
            left.actionRandomnessCommitment,
            right.actionRandomnessCommitment,
        ) &&
        byteArraysEqual(
            left.authorizedEmptyPlaintext,
            right.authorizedEmptyPlaintext,
        ) &&
        byteArraysEqual(
            left.localRecordIdentifier,
            right.localRecordIdentifier,
        ) &&
        byteArraysEqual(left.stateKey, right.stateKey) &&
        byteArraysEqual(
            left.subjectParticipantIdentity,
            right.subjectParticipantIdentity,
        ) &&
        byteArraysEqual(
            left.witnessParticipantIdentity,
            right.witnessParticipantIdentity,
        );
    let committedInitializationCount = 0;
    const createCommittedInitialization =
        (): WebLockCommittedBrowserFoundationInitialization => {
            const initializationIndex = committedInitializationCount;
            committedInitializationCount += 1;
            const retainedActionRandomness =
                initializationIndex === 0
                    ? stateCleanupActionRandomness
                    : undefined;
            const actionRandomnessCommitment =
                retainedActionRandomness?.actionRandomnessCommitment.slice() ??
                new Uint8Array(64).fill(0x21 + initializationIndex);
            retainedActionRandomness?.actionRandomnessCommitment.fill(0);
            const orderedWitnessRecords =
                initializationIndex === 1 &&
                input?.firstAdditionalInitializationWitnessCount !== undefined
                    ? witnessRecords.slice(
                          0,
                          input.firstAdditionalInitializationWitnessCount,
                      )
                    : witnessRecords;
            return Object.freeze({
                actionRandomnessCommitment,
                actionRandomnessSessionIdentifier:
                    retainedActionRandomness?.actionRandomnessSessionIdentifier ??
                    (10 + (initializationIndex % 6)).toString(16).repeat(64),
                freshnessCoordinate: baselineFoundationCoordinate(),
                orderedWitnessRecords: Object.freeze(
                    orderedWitnessRecords.map(copyWitnessRecord),
                ),
            });
        };
    const failedActionRandomnessCloseAttempts = new Set(
        input?.failActionRandomnessCloseAttemptNumbers,
    );
    let actionRandomnessCloseAttemptCount = 0;
    let foundationWitnessCloseAttemptCount = 0;
    let failedFirstFoundationWitnessClose = false;
    const failedFoundationWitnessCloseAttempts = new Set(
        input?.failFoundationWitnessCloseAttemptNumbers,
    );
    let ownedCustodyCloseCount = 0;
    const custodyFacade = Object.freeze({
        closeActionRandomness: async (identifier: string) => {
            actionRandomnessCloseAttemptCount += 1;
            if (
                failedActionRandomnessCloseAttempts.delete(
                    actionRandomnessCloseAttemptCount,
                )
            ) {
                throw new Error(
                    `Injected action-randomness close failure ${String(actionRandomnessCloseAttemptCount)}.`,
                );
            }
            if (
                identifier ===
                stateCleanupActionRandomness?.actionRandomnessSessionIdentifier
            ) {
                await workerKernel.closeActionRandomness(identifier);
            }
        },
        copyBinding: () => ({
            actionContextHash: binding.actionContextHash.slice(),
            ceremonyContextHash: binding.ceremonyContextHash.slice(),
            participantId: binding.participantId.slice(),
            suiteId: binding.suiteId.slice(),
        }),
        closeActionStateVerifierSession: (identifier: string) =>
            workerKernel.closeActionStateVerifierSession(identifier),
        openActionStateVerifierSession: (
            sessionInput: Parameters<
                typeof workerKernel.openActionStateVerifierSession
            >[0],
        ) => workerKernel.openActionStateVerifierSession(sessionInput),
    }) as unknown as BrowserActionStorageCustody;
    const ownedCustody = Object.freeze({
        authenticateFoundationHead: coordinateForCurrentStore,
        close: async () => {
            ownedCustodyCloseCount += 1;
            await workerKernel.destroyActiveActionStorageRoot();
        },
        commitFreshFoundationInitialization: async () => {
            if (
                committedInitializationCount > 0 &&
                input?.additionalInitializationCommitGate !== undefined
            ) {
                input.onAdditionalInitializationCommitStarted?.();
                await input.additionalInitializationCommitGate;
            }
            return createCommittedInitialization();
        },
        custody: custodyFacade,
        openCheckpointStore: () => {
            transferableCheckpointStore ??= openAuthenticatedCheckpointStore({
                authorityContext: runtimeAuthorityContext({
                    actionContextHash: binding.actionContextHash,
                    ceremonyContextHash: binding.ceremonyContextHash,
                    ownerParticipantIdentity: binding.participantId,
                    suiteIdentifier: binding.suiteId,
                }),
                boundaryPolicy: commonProofCheckpointBoundaryPolicy,
                cryptoProvider,
                encryptionKey,
                limits: commonProofCheckpointLimits,
                store: checkpointStorage.store,
            });
            return Promise.resolve(transferableCheckpointStore);
        },
        openCommonProofCustody: async (commonProofInput) => {
            const attemptLogicalRecordPrefix =
                deriveCommonProofAttemptLogicalRecordPrefix(commonProofInput);
            const capacityReservation =
                await storage.store.reserveExclusiveCapacity({
                    initialLogicalRecordKeyPrefixes: [
                        attemptLogicalRecordPrefix,
                        commonProofApplicationHandoffLogicalRecordKey,
                    ],
                    maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength:
                        commonProofStorageCapacityProfile.maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength,
                    maximumAdditionalOwnedRecordCount:
                        commonProofStorageCapacityProfile.maximumAdditionalOwnedRecordCount,
                    maximumAdditionalStoredValueByteLength:
                        commonProofStorageCapacityProfile.maximumAdditionalStoredValueByteLength,
                    maximumDeletionBatchRecordCount:
                        commonProofStorageCapacityProfile.maximumLeaseCountPerTransaction,
                });
            let checkpointPhysicalAccountingScope:
                | AuthenticatedCheckpointPhysicalAccountingScope
                | undefined;
            try {
                if (commonProofInput.checkpoint !== undefined) {
                    const checkpointLineageIdentifier =
                        'operationIdentity' in commonProofInput.checkpoint
                            ? commonProofInput.checkpoint.operationIdentity
                                  .checkpointLineageIdentifier
                            : commonProofInput.checkpoint.resumeDescriptor.checkpointLineageIdentifier.slice();
                    try {
                        checkpointPhysicalAccountingScope =
                            await commonProofInput.checkpoint.store.openPhysicalAccountingScope(
                                checkpointLineageIdentifier,
                            );
                    } finally {
                        checkpointLineageIdentifier.fill(0);
                    }
                }
                const {
                    checkpoint: configuredCheckpoint,
                    ...commonProofInputWithoutCheckpoint
                } = commonProofInput;
                const commonProofCustody = openCommonProofBrowserCustody({
                    ...commonProofInputWithoutCheckpoint,
                    capacityReservation,
                    ...(configuredCheckpoint === undefined ||
                    checkpointPhysicalAccountingScope === undefined
                        ? {}
                        : {
                              checkpoint: {
                                  ...configuredCheckpoint,
                                  physicalAccountingScope:
                                      checkpointPhysicalAccountingScope,
                              },
                          }),
                    limits: {
                        maximumExternalMemoryByteLength: 1_073_741_824n,
                        maximumExternalMemoryObjectCount: 4_096,
                        maximumExternalMemoryRecordCount: 17_749,
                        transactionLifetimeMilliseconds: 10_000,
                    },
                    store: storage.store,
                    workerKernel,
                });
                return (
                    input?.decorateCommonProofCustody?.(commonProofCustody) ??
                    commonProofCustody
                );
            } catch (error) {
                if (
                    commonProofInput.checkpoint !== undefined &&
                    checkpointPhysicalAccountingScope !== undefined
                ) {
                    await commonProofInput.checkpoint.store.releasePhysicalAccountingScope(
                        checkpointPhysicalAccountingScope,
                    );
                }
                await capacityReservation.release();
                throw error;
            }
        },
        openFoundationWitnessRole: (
            witnessRoleInput,
        ): Promise<WebLockOwnedFoundationWitnessRole> => {
            const expectedWitnessRecord =
                witnessRecords[witnessRoleInput.record.roleIndex];
            if (
                expectedWitnessRecord === undefined ||
                !witnessRecordsEqual(
                    witnessRoleInput.record,
                    expectedWitnessRecord,
                )
            ) {
                throw new Error(
                    'Foundation activation did not preserve the exact retained witness record.',
                );
            }
            const witnessRoleIndex = openedFoundationWitnessRoleCount;
            openedFoundationWitnessRoleCount += 1;
            const durableStateService = openDurableStateWitnessService({
                authorityContext: runtimeAuthorityContext({
                    actionContextHash: binding.actionContextHash,
                    ceremonyContextHash: binding.ceremonyContextHash,
                    ownerParticipantIdentity: binding.participantId,
                    suiteIdentifier: binding.suiteId,
                }),
                encryptionKey,
                limits: foundationWitnessServiceLimits,
                store: storage.store,
            });
            const exposedDurableStateService =
                input?.failFirstFoundationWitnessClose === true ||
                input?.failFoundationWitnessCloseAttemptNumbers !== undefined
                    ? Object.freeze({
                          ...durableStateService,
                          claimExclusiveOwner: () => {
                              const claimed =
                                  durableStateService.claimExclusiveOwner();
                              return Object.freeze({
                                  ...claimed,
                                  close: async () => {
                                      foundationWitnessCloseAttemptCount += 1;
                                      if (
                                          failedFoundationWitnessCloseAttempts.delete(
                                              foundationWitnessCloseAttemptCount,
                                          ) ||
                                          (witnessRoleIndex === 0 &&
                                              !failedFirstFoundationWitnessClose)
                                      ) {
                                          failedFirstFoundationWitnessClose = true;
                                          throw new Error(
                                              'Injected fail-once foundation witness close.',
                                          );
                                      }
                                      await claimed.close();
                                  },
                              });
                          },
                      })
                    : durableStateService;
            return Promise.resolve(
                Object.freeze({
                    durableStateService: exposedDurableStateService,
                }),
            );
        },
        openRecoveredFoundationInitialization: () =>
            Promise.reject(
                new Error(
                    'The common-proof application test does not recover initialization.',
                ),
            ),
        openRootAndAuthenticatedStore: () =>
            Promise.reject(
                new Error(
                    'The common-proof application test activates the root directly.',
                ),
            ),
        openRuntimeRecordProtection: () =>
            Promise.reject(
                new Error(
                    'The common-proof application test does not open record protection.',
                ),
            ),
        retire: () => Promise.resolve(),
        state: () => 'open' as const,
    }) as WebLockOwnedBrowserActionStorageCustody;
    const workerScope = new SameRealmCustodyWorkerScope();
    const uninstall = installBrowserActionStorageCustodyWorkerHost({
        foundationWitnessRuntime: {
            durableStateLimits: foundationWitnessServiceLimits,
            openVerifiedStateDurableBinding: () =>
                Promise.resolve({
                    isValid: true,
                    value: stateAuthority.binding,
                }),
            openWitnessCryptography: () => ({
                stateObjectSignatureOperation: Object.freeze({
                    signStateObjectMessage: (signatureMessageHash) =>
                        signCanonicalCarrierFixtureMessage(
                            signatureMessageHash,
                            witnessSigningSecretKey,
                        ),
                }),
            }),
        },
        checkpointStore: {
            boundaryPolicy: commonProofCheckpointBoundaryPolicy,
            limits: commonProofCheckpointLimits,
        },
        cryptoProvider,
        openOwnedCustody: () => Promise.resolve(ownedCustody),
        workerKernel,
        workerScope,
    });
    const workerConfiguration: BrowserActionStorageCustodyWorkerConfiguration =
        Object.freeze({
            acquisitionDeadlineEpochMilliseconds: undefined,
            binding,
            databaseName: 'same-realm-common-proof-application-test',
            knownStorageRootCommitment: undefined,
            limits: foundationStorageTransactionLimits,
            namespace: 'same-realm-proof',
            runtimeBuildManifestHash: new Uint8Array(64).fill(0x73),
        });
    await workerScope.send('open-custody', workerConfiguration);
    const initializationInput: BrowserFoundationInitializationInput =
        Object.freeze({
            actionRandomnessRecordContext: { recordVersion: 0n },
            canonicalRosterBytes:
                stateAuthority.stateVector.canonicalRosterBytes.slice(),
            orderedWitnessBindings: Object.freeze(
                witnessRecords.map((record) => ({
                    subjectParticipantIdentity:
                        record.subjectParticipantIdentity.slice(),
                    witnessParticipantIdentity:
                        record.witnessParticipantIdentity.slice(),
                })),
            ),
            runtimeBuildManifestHash: new Uint8Array(64).fill(0x73),
        });
    const committed = (await workerScope.send(
        'commit-foundation-operation-initialization',
        initializationInput,
    )) as Readonly<{ batchIdentifier: string }>;
    const activated = (await workerScope.send(
        'activate-fresh-foundation-initialization',
        committed.batchIdentifier,
    )) as Readonly<{
        actionRandomnessHandleIdentifier: string;
        orderedWitnessRoleHandleIdentifiers: readonly string[];
    }>;
    const witnessRoleIdentifier =
        activated.orderedWitnessRoleHandleIdentifiers[0];
    if (witnessRoleIdentifier === undefined) {
        await uninstall();
        cancelStateAuthoritySession();
        throw new Error('The same-realm custody host opened no witness role.');
    }
    let closed = false;
    const close = async (): Promise<void> => {
        if (closed) {
            return;
        }
        await uninstall();
        stateAuthority.session.cancel();
        witnessSigningSecretKey.fill(0);
        closed = true;
    };
    const retainAdditionalFoundationInitializationBatches = async () => {
        await commitAdditionalFoundationOperationInitialization();
        await workerScope.send('commit-fresh-foundation-initialization', {
            actionRandomnessRecordContext:
                initializationInput.actionRandomnessRecordContext,
            orderedWitnessBindings: initializationInput.orderedWitnessBindings,
            runtimeBuildManifestHash:
                initializationInput.runtimeBuildManifestHash,
        });
    };
    const commitAdditionalFoundationOperationInitialization =
        async (): Promise<string> => {
            const additionalCommitted = (await workerScope.send(
                'commit-foundation-operation-initialization',
                initializationInput,
            )) as Readonly<{ batchIdentifier: string }>;
            return additionalCommitted.batchIdentifier;
        };
    const activateFreshFoundationInitialization = async (
        batchIdentifier: string,
    ): Promise<
        Readonly<{
            actionRandomnessHandleIdentifier: string;
            orderedWitnessRoleHandleIdentifiers: readonly string[];
        }>
    > =>
        (await workerScope.send(
            'activate-fresh-foundation-initialization',
            batchIdentifier,
        )) as Readonly<{
            actionRandomnessHandleIdentifier: string;
            orderedWitnessRoleHandleIdentifiers: readonly string[];
        }>;
    const retainFoundationStateReservationIntent =
        async (): Promise<string> => {
            cancelStateAuthoritySession();
            const openedStateVerifierSession = (await workerScope.send(
                'open-state-verifier-session',
                {
                    canonicalRosterBytes:
                        stateAuthority.stateVector.canonicalRosterBytes,
                },
            )) as
                | Readonly<{ isValid: false; refusalReason: string }>
                | Readonly<{ isValid: true; value: string }>;
            if (!openedStateVerifierSession.isValid) {
                throw new Error(openedStateVerifierSession.refusalReason);
            }
            try {
                const produced = (await workerScope.send(
                    'produce-foundation-action-randomness-reservation-intent',
                    {
                        actionRandomnessHandleIdentifier:
                            activated.actionRandomnessHandleIdentifier,
                        stateVerifierSessionIdentifier:
                            openedStateVerifierSession.value,
                    },
                )) as
                    | Readonly<{ isValid: false; refusalReason: string }>
                    | Readonly<{
                          isValid: true;
                          value: Readonly<{ stateIntentIdentifier: string }>;
                      }>;
                if (!produced.isValid) {
                    throw new Error(produced.refusalReason);
                }
                return produced.value.stateIntentIdentifier;
            } finally {
                await workerScope.send(
                    'close-state-verifier-session',
                    openedStateVerifierSession.value,
                );
            }
        };
    return Object.freeze({
        actionRandomnessHandleIdentifier:
            activated.actionRandomnessHandleIdentifier,
        activateFreshFoundationInitialization,
        authenticatedFoundationHead: coordinateForCurrentStore,
        close,
        commitAdditionalFoundationOperationInitialization,
        cleanupAttemptCounts: () =>
            Object.freeze({
                actionRandomness: actionRandomnessCloseAttemptCount,
                foundationWitness: foundationWitnessCloseAttemptCount,
                stateObjectRelease: stateObjectReleaseAttemptCount,
            }),
        fixture,
        installedHost: uninstall,
        kernel,
        ownedCustodyCloseCount: () => ownedCustodyCloseCount,
        retainAdditionalFoundationInitializationBatches,
        retainFoundationStateReservationIntent,
        storageAdapter: storage.adapter,
        workerScope,
        witnessRoleIdentifier,
    });
};

export const createInstalledCommonProofGenerationFixture = (
    checkpointCursorBytes: Uint8Array<ArrayBuffer>,
    options: Readonly<{
        checkpointLineageIdentifier: Uint8Array<ArrayBufferLike>;
        failFirstGenerationFamilyAdapterDiscard?: boolean;
        resumeApplicationStatementSchemaIdentifier?: number;
        resumeCheckpointStateByteLength?: number;
    }>,
): Readonly<{
    binding: Uint8Array<ArrayBuffer>;
    checkpointStateBytes: Uint8Array<ArrayBuffer>;
    freshRuntime: TranscriptCoreKernelCommandRuntime;
    observations: {
        acknowledgedCheckpointCount: number;
        cancelledOperationReleaseCount: number;
        discardedGenerationFamilyAdapterCount: number;
        freshStorageResponseCount: number;
        generatedCapabilityReleaseCount: number;
        outputReadbackCount: number;
        prefixReplayResponseCount: number;
    };
    outputBytes: Uint8Array<ArrayBuffer>;
    resumeFamilyPreparationCount(): number;
    resumeRuntime: TranscriptCoreKernelCommandRuntime;
    verificationBinding: Uint8Array<ArrayBuffer>;
}> => {
    expect(options.checkpointLineageIdentifier.byteLength).toBe(32);
    const checkpointLineageIdentifier =
        options.checkpointLineageIdentifier.slice();
    const binding = installedCommonProofGenerationBindingHash.slice();
    const objectBytes = Uint8Array.from([4, 2, 1, 7, 9, 3, 8, 5]);
    const createStorageRequest = encodeRequest({
        maximumPayloadByteLength: 1n,
        operations: [
            {
                kind: 1,
                objectOrdinal: 12,
                payloadByteLength: BigInt(objectBytes.byteLength),
                position: 0n,
                protection: 2,
            },
        ],
        requestSequence: 1n,
        runtimeBindingHash: binding,
    });
    const appendStorageRequest = encodeRequest({
        maximumPayloadByteLength: BigInt(objectBytes.byteLength),
        operations: [
            {
                kind: 2,
                objectOrdinal: 12,
                payload: objectBytes,
                payloadByteLength: BigInt(objectBytes.byteLength),
                position: 0n,
                protection: 0,
            },
        ],
        requestSequence: 2n,
        runtimeBindingHash: binding,
    });
    const sealStorageRequest = encodeRequest({
        maximumPayloadByteLength: 1n,
        operations: [
            {
                kind: 3,
                objectOrdinal: 12,
                payloadByteLength: 0n,
                position: 0n,
                protection: 0,
            },
        ],
        requestSequence: 3n,
        runtimeBindingHash: binding,
    });
    const readStorageRequest = encodeRequest({
        maximumPayloadByteLength: BigInt(objectBytes.byteLength),
        operations: [
            {
                kind: 4,
                objectOrdinal: 12,
                payloadByteLength: BigInt(objectBytes.byteLength),
                position: 0n,
                protection: 0,
            },
        ],
        requestSequence: 4n,
        runtimeBindingHash: binding,
    });
    const freshStorageRequests = Object.freeze([
        createStorageRequest,
        appendStorageRequest,
        sealStorageRequest,
        readStorageRequest,
    ]);
    const checkpointStateBytes = new Uint8Array(37).fill(0x91);
    const stableAttemptBindingHash = binding.slice();
    const outputBytes = Uint8Array.from([8, 6, 7, 5, 3, 0, 9]);
    const observations = {
        acknowledgedCheckpointCount: 0,
        cancelledOperationReleaseCount: 0,
        discardedGenerationFamilyAdapterCount: 0,
        freshStorageResponseCount: 0,
        generatedCapabilityReleaseCount: 0,
        outputReadbackCount: 0,
        prefixReplayResponseCount: 0,
    };
    let freshPhase:
        | 'storage'
        | 'checkpoint'
        | 'awaiting-cancellation'
        | 'cancelled' = 'storage';
    let cancellationRequested = false;
    let freshStorageRequestIndex = 0;
    let generationFamilyAdapterDiscardFailed = false;
    const discardGenerationFamilyAdapter = (): number => {
        observations.discardedGenerationFamilyAdapterCount += 1;
        if (
            options.failFirstGenerationFamilyAdapterDiscard === true &&
            !generationFamilyAdapterDiscardFailed
        ) {
            generationFamilyAdapterDiscardFailed = true;
            return 0x0001_0001;
        }
        return 0;
    };
    const freshRuntime = createMockKernelRuntime((memory) => ({
        sealed_lattice_common_proof_describe_generation_family_adapter: (
            adapterHandle,
            runtimeBindingHashOutputPointer,
            verificationBindingHashOutputPointer,
            proofAttemptLineageIdentifierOutputPointer,
            checkpointLineageIdentifierOutputPointer,
            applicationStatementSchemaIdentifierOutputPointer,
            statusPointer,
        ) => {
            expect([101, 103]).toContain(adapterHandle);
            memoryBytes(
                memory,
                runtimeBindingHashOutputPointer,
                hashByteLength,
            ).set(binding);
            memoryBytes(
                memory,
                verificationBindingHashOutputPointer,
                hashByteLength,
            ).set(installedCommonProofVerificationBindingHash);
            memoryBytes(
                memory,
                proofAttemptLineageIdentifierOutputPointer,
                installedProofAttemptLineageIdentifier.byteLength,
            ).set(installedProofAttemptLineageIdentifier);
            memoryBytes(
                memory,
                checkpointLineageIdentifierOutputPointer,
                checkpointLineageIdentifier.byteLength,
            ).set(checkpointLineageIdentifier);
            writeUnsigned32(
                memory,
                applicationStatementSchemaIdentifierOutputPointer,
                commonProofApplicationStatementSchemaIdentifier,
            );
            writeUnsigned32(memory, statusPointer, 0);
            return 0;
        },
        sealed_lattice_common_proof_prepare_generation_family_adapter: (
            adapterHandle,
            checkpointPointer,
            checkpointByteLength,
            generationCursorManifestPointer,
            generationCursorManifestByteLength,
            statusPointer,
        ) => {
            expect([101, 103]).toContain(adapterHandle);
            expect(checkpointPointer).toBe(0);
            expect(checkpointByteLength).toBe(0);
            expect(generationCursorManifestPointer).toBe(0);
            expect(generationCursorManifestByteLength).toBe(0);
            writeUnsigned32(memory, statusPointer, 0);
            return adapterHandle === 101 ? 201 : 203;
        },
        sealed_lattice_common_proof_discard_generation_family_adapter: (
            adapterHandle,
        ) => {
            expect([101, 103]).toContain(adapterHandle);
            return discardGenerationFamilyAdapter();
        },
        sealed_lattice_common_proof_discard_prepared_generation: (
            preparedGenerationHandle,
        ) => {
            if (preparedGenerationHandle === 201) {
                return 0x0001_0001;
            }
            expect(preparedGenerationHandle).toBe(203);
            throw new Error(
                'The installed family-adapter flow must not discard an unstarted prepared operation.',
            );
        },
        sealed_lattice_common_proof_begin_generation: (
            preparedGenerationHandle,
            statusPointer,
        ) => {
            expect(preparedGenerationHandle).toBe(201);
            writeUnsigned32(memory, statusPointer, 0);
            return 301;
        },
        sealed_lattice_common_proof_generation_poll: (
            operationHandle,
            pollKindPointer,
            primaryValuePointer,
            secondaryValuePointer,
        ) => {
            expect(operationHandle).toBe(301);
            if (freshPhase === 'storage') {
                const currentStorageRequest =
                    freshStorageRequests[freshStorageRequestIndex];
                if (currentStorageRequest === undefined) {
                    throw new Error(
                        'The fresh generation fixture exhausted its storage requests.',
                    );
                }
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    2,
                    currentStorageRequest.byteLength,
                    noSecondPollValue,
                );
            }
            if (freshPhase === 'checkpoint') {
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    1,
                    6,
                    1,
                );
            }
            expect(freshPhase).toBe('awaiting-cancellation');
            expect(cancellationRequested).toBe(true);
            freshPhase = 'cancelled';
            return writeGenerationPoll(
                memory,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
                6,
                0,
                noSecondPollValue,
            );
        },
        sealed_lattice_common_proof_generation_copy_storage_request: (
            operationHandle,
            outputPointer,
            outputByteLength,
        ) => {
            expect(operationHandle).toBe(301);
            const currentStorageRequest =
                freshStorageRequests[freshStorageRequestIndex];
            if (currentStorageRequest === undefined) {
                throw new Error(
                    'The fresh generation fixture exhausted its storage requests.',
                );
            }
            expect(outputByteLength).toBe(currentStorageRequest.byteLength);
            memoryBytes(memory, outputPointer, outputByteLength).set(
                currentStorageRequest,
            );
            return 0;
        },
        sealed_lattice_common_proof_generation_supply_storage_response: (
            operationHandle,
            _responsePointer,
            responseByteLength,
        ) => {
            expect(operationHandle).toBe(301);
            expect(freshPhase).toBe('storage');
            expect(responseByteLength).toBeGreaterThan(0);
            observations.freshStorageResponseCount += 1;
            freshStorageRequestIndex += 1;
            if (freshStorageRequestIndex === freshStorageRequests.length) {
                freshPhase = 'checkpoint';
            }
            return 0;
        },
        sealed_lattice_common_proof_generation_checkpoint_state_byte_length:
            () => checkpointStateBytes.byteLength,
        sealed_lattice_common_proof_generation_describe_checkpoint: (
            operationHandle,
            safeBoundaryOrdinalPointer,
            stateByteLengthPointer,
            cursorManifestByteLengthPointer,
        ) => {
            expect(operationHandle).toBe(301);
            expect(freshPhase).toBe('checkpoint');
            writeUnsigned32(memory, safeBoundaryOrdinalPointer, 0);
            writeUnsigned32(
                memory,
                stateByteLengthPointer,
                checkpointStateBytes.byteLength,
            );
            writeUnsigned32(
                memory,
                cursorManifestByteLengthPointer,
                checkpointCursorBytes.byteLength,
            );
            return 0;
        },
        sealed_lattice_common_proof_generation_copy_checkpoint_state: (
            operationHandle,
            outputPointer,
            outputByteLength,
        ) => {
            expect(operationHandle).toBe(301);
            expect(outputByteLength).toBe(checkpointStateBytes.byteLength);
            memoryBytes(memory, outputPointer, outputByteLength).set(
                checkpointStateBytes,
            );
            return 0;
        },
        sealed_lattice_common_proof_generation_copy_checkpoint_cursor_manifest:
            (operationHandle, outputPointer, outputByteLength) => {
                expect(operationHandle).toBe(301);
                expect(outputByteLength).toBe(checkpointCursorBytes.byteLength);
                memoryBytes(memory, outputPointer, outputByteLength).set(
                    checkpointCursorBytes,
                );
                return 0;
            },
        sealed_lattice_common_proof_generation_copy_checkpoint_stable_attempt_binding_hash:
            (operationHandle, outputPointer, outputByteLength) => {
                expect(operationHandle).toBe(301);
                expect(outputByteLength).toBe(hashByteLength);
                memoryBytes(memory, outputPointer, outputByteLength).set(
                    stableAttemptBindingHash,
                );
                return 0;
            },
        sealed_lattice_common_proof_generation_acknowledge_checkpoint: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(301);
            expect(freshPhase).toBe('checkpoint');
            observations.acknowledgedCheckpointCount += 1;
            freshPhase = 'awaiting-cancellation';
            return 0;
        },
        sealed_lattice_common_proof_generation_request_cancellation: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(301);
            expect(freshPhase).toBe('awaiting-cancellation');
            cancellationRequested = true;
            return 0;
        },
        sealed_lattice_common_proof_generation_release_cancelled: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(301);
            expect(freshPhase).toBe('cancelled');
            observations.cancelledOperationReleaseCount += 1;
            return 0;
        },
        sealed_lattice_common_proof_generation_retire_failed: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(301);
            return 0;
        },
    }));

    let resumePhase:
        | 'replay'
        | 'resume-complete'
        | 'output'
        | 'readback'
        | 'complete'
        | 'finished' = 'replay';
    let resumeStorageRequestIndex = 0;
    let resumeFamilyPreparationCount = 0;
    const resumeRuntime = createMockKernelRuntime((memory) => ({
        sealed_lattice_common_proof_describe_generation_family_adapter: (
            adapterHandle,
            runtimeBindingHashOutputPointer,
            verificationBindingHashOutputPointer,
            proofAttemptLineageIdentifierOutputPointer,
            checkpointLineageIdentifierOutputPointer,
            applicationStatementSchemaIdentifierOutputPointer,
            statusPointer,
        ) => {
            expect(adapterHandle).toBe(102);
            memoryBytes(
                memory,
                runtimeBindingHashOutputPointer,
                hashByteLength,
            ).set(binding);
            memoryBytes(
                memory,
                verificationBindingHashOutputPointer,
                hashByteLength,
            ).set(installedCommonProofVerificationBindingHash);
            memoryBytes(
                memory,
                proofAttemptLineageIdentifierOutputPointer,
                installedProofAttemptLineageIdentifier.byteLength,
            ).set(installedProofAttemptLineageIdentifier);
            memoryBytes(
                memory,
                checkpointLineageIdentifierOutputPointer,
                checkpointLineageIdentifier.byteLength,
            ).set(checkpointLineageIdentifier);
            writeUnsigned32(
                memory,
                applicationStatementSchemaIdentifierOutputPointer,
                options.resumeApplicationStatementSchemaIdentifier ??
                    commonProofApplicationStatementSchemaIdentifier,
            );
            writeUnsigned32(memory, statusPointer, 0);
            return 0;
        },
        sealed_lattice_common_proof_prepare_generation_family_adapter: (
            adapterHandle,
            checkpointPointer,
            checkpointByteLength,
            generationCursorManifestPointer,
            generationCursorManifestByteLength,
            statusPointer,
        ) => {
            expect(adapterHandle).toBe(102);
            resumeFamilyPreparationCount += 1;
            expect([
                ...memoryBytes(memory, checkpointPointer, checkpointByteLength),
            ]).toEqual([...checkpointStateBytes]);
            expect([
                ...memoryBytes(
                    memory,
                    generationCursorManifestPointer,
                    generationCursorManifestByteLength,
                ),
            ]).toEqual([...checkpointCursorBytes]);
            writeUnsigned32(memory, statusPointer, 0);
            return 202;
        },
        sealed_lattice_common_proof_discard_generation_family_adapter: (
            adapterHandle,
        ) => {
            expect(adapterHandle).toBe(102);
            return discardGenerationFamilyAdapter();
        },
        sealed_lattice_common_proof_generation_checkpoint_state_byte_length:
            () =>
                options.resumeCheckpointStateByteLength ??
                checkpointStateBytes.byteLength,
        sealed_lattice_common_proof_resume_generation: (
            preparedGenerationHandle,
            checkpointPointer,
            checkpointByteLength,
            generationCursorManifestPointer,
            generationCursorManifestByteLength,
            statusPointer,
        ) => {
            expect(preparedGenerationHandle).toBe(202);
            expect([
                ...memoryBytes(memory, checkpointPointer, checkpointByteLength),
            ]).toEqual([...checkpointStateBytes]);
            expect([
                ...memoryBytes(
                    memory,
                    generationCursorManifestPointer,
                    generationCursorManifestByteLength,
                ),
            ]).toEqual([...checkpointCursorBytes]);
            writeUnsigned32(memory, statusPointer, 0);
            return 302;
        },
        sealed_lattice_common_proof_generation_poll: (
            operationHandle,
            pollKindPointer,
            primaryValuePointer,
            secondaryValuePointer,
        ) => {
            expect(operationHandle).toBe(302);
            if (resumePhase === 'replay') {
                const currentStorageRequest =
                    freshStorageRequests[resumeStorageRequestIndex];
                if (currentStorageRequest === undefined) {
                    throw new Error(
                        'The resumed generation fixture exhausted its replay requests.',
                    );
                }
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    2,
                    currentStorageRequest.byteLength,
                    noSecondPollValue,
                );
            }
            if (resumePhase === 'resume-complete') {
                resumePhase = 'output';
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    7,
                    6,
                    noSecondPollValue,
                );
            }
            if (resumePhase === 'output') {
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    3,
                    0,
                    outputBytes.byteLength,
                );
            }
            if (resumePhase === 'readback') {
                return writeGenerationPoll(
                    memory,
                    pollKindPointer,
                    primaryValuePointer,
                    secondaryValuePointer,
                    4,
                    0,
                    noSecondPollValue,
                );
            }
            return writeGenerationPoll(
                memory,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
                5,
                0,
                noSecondPollValue,
            );
        },
        sealed_lattice_common_proof_generation_copy_storage_request: (
            operationHandle,
            outputPointer,
            outputByteLength,
        ) => {
            expect(operationHandle).toBe(302);
            const currentStorageRequest =
                freshStorageRequests[resumeStorageRequestIndex];
            if (currentStorageRequest === undefined) {
                throw new Error(
                    'The resumed generation fixture exhausted its replay requests.',
                );
            }
            expect(outputByteLength).toBe(currentStorageRequest.byteLength);
            memoryBytes(memory, outputPointer, outputByteLength).set(
                currentStorageRequest,
            );
            return 0;
        },
        sealed_lattice_common_proof_generation_supply_storage_response: (
            operationHandle,
            _responsePointer,
            responseByteLength,
        ) => {
            expect(operationHandle).toBe(302);
            expect(resumePhase).toBe('replay');
            expect(responseByteLength).toBeGreaterThan(0);
            observations.prefixReplayResponseCount += 1;
            resumeStorageRequestIndex += 1;
            if (resumeStorageRequestIndex === freshStorageRequests.length) {
                resumePhase = 'resume-complete';
            }
            return 0;
        },
        sealed_lattice_common_proof_generation_copy_output_chunk: (
            operationHandle,
            chunkIndex,
            outputPointer,
            outputByteLength,
        ) => {
            expect(operationHandle).toBe(302);
            expect(chunkIndex).toBe(0);
            expect(outputByteLength).toBe(outputBytes.byteLength);
            memoryBytes(memory, outputPointer, outputByteLength).set(
                outputBytes,
            );
            return 0;
        },
        sealed_lattice_common_proof_generation_acknowledge_output_chunk: (
            operationHandle,
            chunkIndex,
        ) => {
            expect(operationHandle).toBe(302);
            expect(chunkIndex).toBe(0);
            expect(resumePhase).toBe('output');
            resumePhase = 'readback';
            return 0;
        },
        sealed_lattice_common_proof_generation_confirm_output_readback: (
            operationHandle,
            chunkIndex,
            readbackPointer,
            readbackByteLength,
        ) => {
            expect(operationHandle).toBe(302);
            expect(chunkIndex).toBe(0);
            expect([
                ...memoryBytes(memory, readbackPointer, readbackByteLength),
            ]).toEqual([...outputBytes]);
            observations.outputReadbackCount += 1;
            resumePhase = 'complete';
            return 0;
        },
        sealed_lattice_common_proof_generation_finish: (
            operationHandle,
            statusPointer,
        ) => {
            expect(operationHandle).toBe(302);
            expect(resumePhase).toBe('complete');
            writeUnsigned32(memory, statusPointer, 0);
            resumePhase = 'finished';
            return 402;
        },
        sealed_lattice_common_proof_release_generated_proof: (
            capabilityHandle,
        ) => {
            expect(capabilityHandle).toBe(402);
            expect(resumePhase).toBe('finished');
            observations.generatedCapabilityReleaseCount += 1;
            return 0;
        },
        sealed_lattice_common_proof_generation_retire_failed: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(302);
            return 0;
        },
    }));

    return Object.freeze({
        binding,
        checkpointStateBytes,
        freshRuntime,
        observations,
        outputBytes,
        resumeFamilyPreparationCount: () => resumeFamilyPreparationCount,
        resumeRuntime,
        verificationBinding:
            installedCommonProofVerificationBindingHash.slice(),
    });
};

export const openReservedInstalledCommonProofGenerationFixture = async (
    host: Pick<
        Awaited<ReturnType<typeof openSameRealmCommonProofApplicationHost>>,
        'installedHost'
    >,
    checkpointCursorBytes: Uint8Array<ArrayBuffer>,
    options: Readonly<{
        failFirstGenerationFamilyAdapterDiscard?: boolean;
        generationFamilyAdapterHandle?: 101 | 103;
        resumeApplicationStatementSchemaIdentifier?: number;
        resumeCheckpointStateByteLength?: number;
    }> = {},
): Promise<
    Readonly<{
        checkpointLineageReservation: InstalledCommonProofCheckpointLineageReservation;
        generationFamilyAdapter: ClosedWorkerCommonProofGenerationFamilyAdapter;
        generationFixture: ReturnType<
            typeof createInstalledCommonProofGenerationFixture
        >;
    }>
> => {
    const { generationFamilyAdapterHandle = 101, ...generationFixtureOptions } =
        options;
    const checkpointLineageReservation =
        await reserveCommonProofCheckpointLineageInInstalledCustodyWorker(
            host.installedHost,
        );
    const checkpointLineageIdentifier =
        copyReservedCommonProofCheckpointLineageIdentifier(
            checkpointLineageReservation,
        );
    let generationFamilyAdapter:
        | ReturnType<typeof openClosedWorkerCommonProofGenerationFamilyAdapter>
        | undefined;
    try {
        const generationFixture = createInstalledCommonProofGenerationFixture(
            checkpointCursorBytes,
            {
                ...generationFixtureOptions,
                checkpointLineageIdentifier,
            },
        );
        generationFamilyAdapter =
            openClosedWorkerCommonProofGenerationFamilyAdapter(
                generationFixture.freshRuntime,
                generationFamilyAdapterHandle,
            );
        return Object.freeze({
            checkpointLineageReservation,
            generationFamilyAdapter,
            generationFixture,
        });
    } catch (error) {
        const cleanupFailures: unknown[] = [];
        if (generationFamilyAdapter !== undefined) {
            try {
                releaseClosedWorkerCommonProofGenerationFamilyAdapter(
                    generationFamilyAdapter,
                );
            } catch (cleanupError) {
                cleanupFailures.push(cleanupError);
            }
        }
        try {
            await releaseReservedCommonProofCheckpointLineageInInstalledCustodyWorker(
                host.installedHost,
                checkpointLineageReservation,
            );
        } catch (cleanupError) {
            cleanupFailures.push(cleanupError);
        }
        if (cleanupFailures.length !== 0) {
            throw new BrowserActionStorageCustodyError(
                'StorageFailure',
                'Opening the reserved installed common-proof fixture failed and cleanup did not complete.',
                Object.freeze([error, ...cleanupFailures]),
            );
        }
        throw error;
    } finally {
        checkpointLineageIdentifier.fill(0);
    }
};

export const openReadyCommonProofApplication = async (): Promise<
    Readonly<{
        durableBindingIdentifier: string;
        environment: InstalledCustodyCommonProofExecutionEnvironment;
        generationFixture: ReturnType<
            typeof createInstalledCommonProofGenerationFixture
        >;
        host: Awaited<
            ReturnType<typeof openSameRealmCommonProofApplicationHost>
        >;
    }>
> => {
    const proofBytes = Uint8Array.from([8, 6, 7, 5, 3, 0, 9]);
    const host = await openSameRealmCommonProofApplicationHost({ proofBytes });
    try {
        const cursorBytes = createCommonProofGenerationCursorFixtureBytes(
            host.kernel,
        );
        const reservedGeneration =
            await openReservedInstalledCommonProofGenerationFixture(
                host,
                cursorBytes,
            );
        const generationFixture = reservedGeneration.generationFixture;
        const preparedOperation =
            await prepareCommonProofGenerationInInstalledCustodyWorker(
                host.installedHost,
                {
                    checkpoint: {
                        generationMode: 'fresh',
                        reservation:
                            reservedGeneration.checkpointLineageReservation,
                    },
                    foundationActionRandomnessHandleIdentifier:
                        host.actionRandomnessHandleIdentifier,
                    generationFamilyAdapter:
                        reservedGeneration.generationFamilyAdapter,
                },
            );
        let environment:
            | InstalledCustodyCommonProofExecutionEnvironment
            | undefined =
            await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                host.installedHost,
                { preparedOperation },
            );
        try {
            const cancellationController = new AbortController();
            await expect(
                runCommonProofGenerationInInstalledCustodyWorker(environment, {
                    signal: cancellationController.signal,
                    yieldControl: () => {
                        cancellationController.abort(
                            'participant interrupted generation',
                        );
                        return Promise.resolve();
                    },
                }),
            ).rejects.toMatchObject({ code: 'Cancelled' });
            const resumeDescriptor =
                await suspendCommonProofExecutionEnvironmentForAuthenticatedResumeInInstalledCustodyWorker(
                    environment,
                );
            environment = undefined;
            const resumedGenerationFamilyAdapter =
                openClosedWorkerCommonProofGenerationFamilyAdapter(
                    generationFixture.resumeRuntime,
                    102,
                );
            try {
                const resumedPreparedOperation =
                    await prepareCommonProofGenerationInInstalledCustodyWorker(
                        host.installedHost,
                        {
                            checkpoint: {
                                generationMode: 'resumed',
                                resumeDescriptor,
                            },
                            foundationActionRandomnessHandleIdentifier:
                                host.actionRandomnessHandleIdentifier,
                            generationFamilyAdapter:
                                resumedGenerationFamilyAdapter,
                        },
                    );
                environment =
                    await openCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                        host.installedHost,
                        { preparedOperation: resumedPreparedOperation },
                    );
            } finally {
                resumeDescriptor.checkpointLineageIdentifier.fill(0);
                resumeDescriptor.commonProofEnvironmentIdentifier.fill(0);
                resumeDescriptor.generationCursorManifestBytes.fill(0);
                resumeDescriptor.privateRandomnessStreamAttemptIdentifier?.fill(
                    0,
                );
                resumeDescriptor.stableAttemptBindingHash.fill(0);
            }
            await runCommonProofGenerationInInstalledCustodyWorker(
                environment,
                { yieldControl: () => Promise.resolve() },
            );
            host.fixture.capability.release();
            const durableBindingIdentifier = (await host.workerScope.send(
                'open-foundation-witness-durable-binding',
                {
                    stateObjectIdentifier: 'c'.repeat(64),
                    witnessRoleIdentifier: host.witnessRoleIdentifier,
                },
            )) as string;
            return Object.freeze({
                durableBindingIdentifier,
                environment,
                generationFixture,
                host,
            });
        } catch (error) {
            if (environment !== undefined) {
                await closeCommonProofExecutionEnvironmentInInstalledCustodyWorker(
                    environment,
                ).catch(() => undefined);
            }
            throw error;
        }
    } catch (error) {
        await host.close().catch(() => undefined);
        throw error;
    }
};
