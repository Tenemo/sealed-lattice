import {
    copyAuthenticatedMailboxFrozenRosterParticipantIdentities,
    openAuthenticatedMailboxFrozenRoster,
} from '@sealed-lattice/crypto';
import {
    foundationProfile,
    stateCapabilityKinds,
    type VerificationResult,
} from '@sealed-lattice/types';
import { afterEach, describe, expect, it } from 'vitest';

import {
    createCanonicalCarrierMailboxKeyPairFixtures,
    createCanonicalCarrierSigningKeyPairFixtures,
} from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';
import type { BrowserDeviceWrappingSnapshot } from '#packages/protocol/src/runtime/browser-action-storage-custody';
import { openBrowserFoundationOperationOwnerWorker } from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';
import {
    type BrowserFoundationActiveCapability,
    type BrowserFoundationActionRandomness,
    type BrowserFoundationAuthority,
    type BrowserFoundationWitnessRole,
    openBrowserFoundationAuthority,
} from '#packages/protocol/src/runtime/browser-foundation-authority-combined';
import type { TransferableBrowserFoundationOperationOwner } from '#packages/protocol/src/runtime/browser-foundation-operation-owner';
import { openCanonicalBoardRuntime } from '#packages/protocol/src/runtime/canonical-board-runtime';
import { deriveWebLockStorageNamespaceName } from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import {
    copyRuntimeBuildAuthorityBindingDescription,
    loadFreshTranscriptCoreKernel,
    type CanonicalBoardContextInput,
    type RuntimeBuildAuthorityBinding,
} from '#packages/wasm/src/index';
import { createCanonicalBoardContextTestInput } from '#packages/wasm/tests/canonical-board-context-test-vector';
import { createCanonicalTestRosterBytes } from '#packages/wasm/tests/canonical-tuple-test-helpers';
import { createStateVerifierTestVector } from '#packages/wasm/tests/state-verifier-test-vectors';
import { activateRuntimeBuildAuthorityBindingFixture } from '#packages/wasm/tests/support/runtime-build-authority-binding-fixture';

const transactionLimits = {
    maximumActiveTransactionCount: 2,
    maximumLeaseByteLength: 65_536,
    maximumLeaseCountPerTransaction: 32,
    maximumOwnedRecordCount: 256,
    maximumStoredValueByteLength: 4_194_304,
    maximumTransactionByteLength: 1_048_576,
    maximumTransactionLifetimeMilliseconds: 10_000,
} as const;
const storageNamespace = 'browser-foundation-authority-real-components';
const requiredWitnessVoteCount = foundationProfile.stateWitnessQuorum;
const indexedDbObjectStoreName = 'records';
const deviceWrappingRecordKind = 'sealed-lattice-device-wrapping-state';
const runtimeStorePrefix = `sealed-lattice-runtime-store/${storageNamespace}/`;
const runtimeIndexPrefix = `${runtimeStorePrefix}indices/`;
const signedVoteLogicalRecordPrefix = 'state-signed-vote-carrier/';
const fatalTextDecoder = new TextDecoder('utf-8', { fatal: true });

type OpenedOperationOwner = Readonly<{
    databaseName: string;
    deviceWrappingSnapshot: BrowserDeviceWrappingSnapshot;
    operationOwner: TransferableBrowserFoundationOperationOwner;
    worker: Worker;
}>;

type OpenedParticipantAuthority = Readonly<{
    actionRandomness: BrowserFoundationActionRandomness;
    authority: BrowserFoundationAuthority;
    capability: BrowserFoundationActiveCapability;
    opening: OpenedOperationOwner;
    rosterPosition: number;
}>;

const liveAuthorities = new Set<BrowserFoundationAuthority>();
const liveWorkers = new Set<Worker>();
const databaseNames = new Set<string>();

const createCanonicalRosterBytes = (): Uint8Array => {
    const signingKeyPairs = createCanonicalCarrierSigningKeyPairFixtures(
        foundationProfile.participantCount,
    );
    const mailboxKeyPairs = createCanonicalCarrierMailboxKeyPairFixtures(
        foundationProfile.participantCount,
    );
    try {
        return createCanonicalTestRosterBytes(
            signingKeyPairs.map(({ publicKey }, rosterPosition) => {
                const mailboxKeyPair = mailboxKeyPairs[rosterPosition];
                if (mailboxKeyPair === undefined) {
                    throw new Error(
                        'The deterministic roster mailbox fixture is incomplete.',
                    );
                }
                return {
                    mailboxEncapsulationKey: mailboxKeyPair.publicKey,
                    signingVerificationKey: publicKey,
                };
            }),
        );
    } finally {
        for (const keyPair of signingKeyPairs) {
            keyPair.secretKey.fill(0);
        }
        for (const keyPair of mailboxKeyPairs) {
            keyPair.secretKey.fill(0);
        }
    }
};

const createDatabaseName = (): string => {
    const randomBytes = new Uint8Array(16);
    crypto.getRandomValues(randomBytes);
    return `sealed-lattice-foundation-authority-${Array.from(
        randomBytes,
        (byte) => byte.toString(16).padStart(2, '0'),
    ).join('')}`;
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= (left[byteIndex] ?? 0) ^ (right[byteIndex] ?? 0);
    }
    return difference === 0;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const decodeHexText = (encodedText: string): string => {
    if (
        encodedText.length === 0 ||
        encodedText.length % 2 !== 0 ||
        !/^[0-9a-f]+$/u.test(encodedText)
    ) {
        throw new Error(
            'The IndexedDB logical-record key is not canonical hex.',
        );
    }
    return fatalTextDecoder.decode(
        Uint8Array.from(
            { length: encodedText.length / 2 },
            (_unused, byteIndex) =>
                Number.parseInt(
                    encodedText.slice(byteIndex * 2, byteIndex * 2 + 2),
                    16,
                ),
        ),
    );
};

const requireValid = <Value>(
    result: VerificationResult<Value>,
    operationDescription: string,
): Value => {
    if (!result.isValid) {
        throw new Error(
            `${operationDescription} was refused: ${result.refusalReason}.`,
        );
    }
    return result.value;
};

const deleteDatabase = (databaseName: string): Promise<void> =>
    new Promise<void>((resolve, reject) => {
        const request = indexedDB.deleteDatabase(databaseName);
        request.addEventListener('success', () => resolve(), { once: true });
        request.addEventListener(
            'error',
            () =>
                reject(
                    request.error ??
                        new Error(
                            'Foundation authority browser database cleanup failed.',
                        ),
                ),
            { once: true },
        );
        request.addEventListener(
            'blocked',
            () =>
                reject(
                    new Error(
                        'Foundation authority browser database cleanup was blocked by a retained worker connection.',
                    ),
                ),
            { once: true },
        );
    });

const openExistingDatabase = (databaseName: string): Promise<IDBDatabase> =>
    new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open(databaseName, 1);
        request.addEventListener(
            'upgradeneeded',
            () => {
                request.transaction?.abort();
                reject(
                    new Error(
                        'The expected browser foundation database does not exist.',
                    ),
                );
            },
            { once: true },
        );
        request.addEventListener('success', () => resolve(request.result), {
            once: true,
        });
        request.addEventListener(
            'error',
            () =>
                reject(
                    request.error ??
                        new Error(
                            'Opening the browser foundation database for fault injection failed.',
                        ),
                ),
            { once: true },
        );
    });

const listDatabaseRecords = (
    database: IDBDatabase,
): Promise<ReadonlyMap<string, unknown>> =>
    new Promise<ReadonlyMap<string, unknown>>((resolve, reject) => {
        const records = new Map<string, unknown>();
        let scanFailure: unknown;
        const transaction = database.transaction(
            indexedDbObjectStoreName,
            'readonly',
        );
        const request = transaction
            .objectStore(indexedDbObjectStoreName)
            .openCursor();
        request.addEventListener('success', () => {
            const cursor = request.result;
            if (cursor === null) {
                return;
            }
            if (typeof cursor.key !== 'string') {
                scanFailure = new Error(
                    'The browser foundation database contains a non-string key.',
                );
                transaction.abort();
                return;
            }
            records.set(cursor.key, cursor.value as unknown);
            cursor.continue();
        });
        request.addEventListener('error', () => {
            scanFailure =
                request.error ??
                new Error('Scanning browser foundation records failed.');
        });
        transaction.addEventListener('complete', () => resolve(records), {
            once: true,
        });
        transaction.addEventListener(
            'abort',
            () => {
                const failure = scanFailure ?? transaction.error;
                reject(
                    failure instanceof Error
                        ? failure
                        : Object.assign(
                              new Error(
                                  'Scanning browser foundation records was aborted.',
                              ),
                              { failureCause: failure },
                          ),
                );
            },
            { once: true },
        );
        transaction.addEventListener(
            'error',
            () => {
                scanFailure ??=
                    transaction.error ??
                    new Error('Scanning browser foundation records failed.');
            },
            { once: true },
        );
    });

const applyDatabaseMutations = (
    database: IDBDatabase,
    mutations: readonly (
        | Readonly<{ key: string; operation: 'delete' }>
        | Readonly<{
              key: string;
              operation: 'write';
              value: Uint8Array;
          }>
    )[],
): Promise<void> =>
    new Promise<void>((resolve, reject) => {
        const transaction = database.transaction(
            indexedDbObjectStoreName,
            'readwrite',
            { durability: 'strict' },
        );
        const objectStore = transaction.objectStore(indexedDbObjectStoreName);
        for (const mutation of mutations) {
            if (mutation.operation === 'delete') {
                objectStore.delete(mutation.key);
            } else {
                objectStore.put(mutation.value, mutation.key);
            }
        }
        transaction.addEventListener('complete', () => resolve(), {
            once: true,
        });
        transaction.addEventListener(
            'abort',
            () =>
                reject(
                    transaction.error ??
                        new Error(
                            'The browser foundation fault-injection transaction was aborted.',
                        ),
                ),
            { once: true },
        );
        transaction.addEventListener(
            'error',
            () =>
                reject(
                    transaction.error ??
                        new Error(
                            'The browser foundation fault-injection transaction failed.',
                        ),
                ),
            { once: true },
        );
    });

const tamperAuthenticatedSignedVoteRecords = async (
    databaseName: string,
): Promise<void> => {
    const database = await openExistingDatabase(databaseName);
    try {
        const records = await listDatabaseRecords(database);
        const signedVoteObjectKeys = new Set<string>();
        for (const [key, value] of records) {
            if (!key.startsWith(runtimeIndexPrefix)) {
                continue;
            }
            const logicalRecordKey = decodeHexText(
                key.slice(runtimeIndexPrefix.length),
            );
            if (!logicalRecordKey.startsWith(signedVoteLogicalRecordPrefix)) {
                continue;
            }
            if (!(value instanceof Uint8Array)) {
                throw new Error(
                    'The signed-vote index does not name a byte-encoded object key.',
                );
            }
            signedVoteObjectKeys.add(fatalTextDecoder.decode(value));
        }
        if (signedVoteObjectKeys.size === 0) {
            throw new Error(
                'The retained signed-vote storage record is unavailable for fault injection.',
            );
        }
        const mutations = [...signedVoteObjectKeys].map((key) => {
            const value = records.get(key);
            if (!(value instanceof Uint8Array) || value.byteLength === 0) {
                throw new Error(
                    'The retained signed-vote object is not a nonempty byte string.',
                );
            }
            const tamperedValue = value.slice();
            tamperedValue[tamperedValue.byteLength - 1] ^= 1;
            return Object.freeze({
                key,
                operation: 'write' as const,
                value: tamperedValue,
            });
        });
        await applyDatabaseMutations(database, mutations);
    } finally {
        database.close();
    }
};

const deleteDeviceWrappingState = async (
    databaseName: string,
): Promise<void> => {
    const database = await openExistingDatabase(databaseName);
    try {
        const records = await listDatabaseRecords(database);
        const matchingKeys = [...records]
            .filter(([_key, value]) => {
                if (typeof value !== 'object' || value === null) {
                    return false;
                }
                return (
                    (value as Readonly<{ recordKind?: unknown }>).recordKind ===
                    deviceWrappingRecordKind
                );
            })
            .map(([key]) => key);
        if (matchingKeys.length !== 1) {
            throw new Error(
                'The browser foundation database does not contain exactly one active device-wrapping state.',
            );
        }
        await applyDatabaseMutations(database, [
            { key: matchingKeys[0], operation: 'delete' },
        ]);
    } finally {
        database.close();
    }
};

const waitForExclusiveLockRelease = (databaseName: string): Promise<void> =>
    navigator.locks.request(
        deriveWebLockStorageNamespaceName({
            databaseName,
            namespace: storageNamespace,
        }),
        { mode: 'exclusive' },
        () => undefined,
    );

const createInterruptedCommonProofApplicationHandoff = async (input: {
    binding: Readonly<{
        actionContextHash: Uint8Array;
        ceremonyContextHash: Uint8Array;
        participantId: Uint8Array;
        suiteId: Uint8Array;
    }>;
    databaseName: string;
    runtimeBuildManifestHash: Uint8Array;
}): Promise<BrowserDeviceWrappingSnapshot> => {
    const worker = new Worker(
        new URL(
            '../support/common-proof-application-handoff-crash-worker.ts',
            import.meta.url,
        ),
        { name: 'sealed-lattice-common-proof-handoff-crash', type: 'module' },
    );
    liveWorkers.add(worker);
    databaseNames.add(input.databaseName);
    try {
        const snapshot = await new Promise<BrowserDeviceWrappingSnapshot>(
            (resolve, reject) => {
                const handleError = (event: ErrorEvent): void => {
                    worker.removeEventListener('message', handleMessage);
                    reject(
                        event.error instanceof Error
                            ? event.error
                            : new Error(
                                  event.message ||
                                      'The common-proof handoff crash worker failed to load.',
                              ),
                    );
                };
                const handleMessage = (event: MessageEvent<unknown>): void => {
                    worker.removeEventListener('error', handleError);
                    const response = event.data;
                    if (
                        typeof response !== 'object' ||
                        response === null ||
                        !('messageKind' in response)
                    ) {
                        reject(
                            new Error(
                                'The common-proof handoff crash worker returned a malformed response.',
                            ),
                        );
                        return;
                    }
                    if (
                        response.messageKind === 'common-proof-handoff-armed' &&
                        'deviceWrappingSnapshot' in response &&
                        typeof response.deviceWrappingSnapshot === 'object' &&
                        response.deviceWrappingSnapshot !== null &&
                        'mutationIdentifier' in
                            response.deviceWrappingSnapshot &&
                        response.deviceWrappingSnapshot
                            .mutationIdentifier instanceof Uint8Array &&
                        'storageRootCommitment' in
                            response.deviceWrappingSnapshot &&
                        response.deviceWrappingSnapshot
                            .storageRootCommitment instanceof Uint8Array
                    ) {
                        resolve(
                            Object.freeze({
                                mutationIdentifier:
                                    response.deviceWrappingSnapshot.mutationIdentifier.slice(),
                                storageRootCommitment:
                                    response.deviceWrappingSnapshot.storageRootCommitment.slice(),
                            }),
                        );
                        return;
                    }
                    reject(
                        Object.assign(
                            new Error(
                                'errorMessage' in response &&
                                    typeof response.errorMessage === 'string'
                                    ? response.errorMessage
                                    : 'The common-proof handoff crash worker refused its operation.',
                            ),
                            {
                                code:
                                    'errorCode' in response
                                        ? response.errorCode
                                        : undefined,
                            },
                        ),
                    );
                };
                worker.addEventListener('error', handleError, { once: true });
                worker.addEventListener('message', handleMessage, {
                    once: true,
                });
                worker.postMessage({
                    binding: input.binding,
                    databaseName: input.databaseName,
                    runtimeBuildManifestHash: input.runtimeBuildManifestHash,
                    storageNamespace,
                });
            },
        );
        return snapshot;
    } finally {
        liveWorkers.delete(worker);
        worker.terminate();
        await waitForExclusiveLockRelease(input.databaseName);
    }
};

const openOperationOwner = async (input: {
    binding: Readonly<{
        actionContextHash: Uint8Array;
        ceremonyContextHash: Uint8Array;
        participantId: Uint8Array;
        suiteId: Uint8Array;
    }>;
    databaseName: string;
    failFirstRetirementWrite?: boolean;
    mode:
        | Readonly<{ kind: 'fresh' }>
        | Readonly<{
              expectedSnapshot: BrowserDeviceWrappingSnapshot;
              kind: 'recovered';
          }>;
    runtimeBuildManifestHash: Uint8Array;
    rosterPosition: number;
}): Promise<OpenedOperationOwner> => {
    const worker = new Worker(
        new URL(
            '../support/browser-foundation-authority-real-components-worker.ts',
            import.meta.url,
        ),
        {
            name: `sealed-lattice-roster-position:${String(input.rosterPosition)}${input.failFirstRetirementWrite === true ? ':fail-first-retirement-write' : ''}`,
            type: 'module',
        },
    );
    liveWorkers.add(worker);
    databaseNames.add(input.databaseName);
    try {
        const opened = await openBrowserFoundationOperationOwnerWorker({
            configuration: {
                binding: input.binding,
                databaseName: input.databaseName,
                ...(input.mode.kind === 'recovered'
                    ? {
                          knownStorageRootCommitment:
                              input.mode.expectedSnapshot.storageRootCommitment,
                      }
                    : {}),
                limits: transactionLimits,
                namespace: storageNamespace,
                runtimeBuildManifestHash: input.runtimeBuildManifestHash,
            },
            rootOpening:
                input.mode.kind === 'fresh'
                    ? { mode: 'fresh' }
                    : {
                          expectedSnapshot: input.mode.expectedSnapshot,
                          mode: 'recovered',
                          untrustedExpectedCommitment: {
                              storageRootCommitment:
                                  input.mode.expectedSnapshot
                                      .storageRootCommitment,
                          },
                      },
            worker,
        });
        return Object.freeze({
            ...opened,
            databaseName: input.databaseName,
            worker,
        });
    } catch (error) {
        liveWorkers.delete(worker);
        worker.terminate();
        throw error;
    }
};

const openAuthority = async (input: {
    canonicalBoardContext: CanonicalBoardContextInput;
    initializationMode: 'fresh' | 'recovered';
    operationOwner: TransferableBrowserFoundationOperationOwner;
    runtimeBuildAuthorityBinding: RuntimeBuildAuthorityBinding;
}): Promise<BrowserFoundationAuthority> => {
    const board = openCanonicalBoardRuntime({
        contextInput: input.canonicalBoardContext,
        kernel: await loadFreshTranscriptCoreKernel(),
    });
    if (!board.isValid) {
        throw new Error(
            `The real browser canonical-board runtime refused its context: ${board.refusalReason}.`,
        );
    }
    const authority = await openBrowserFoundationAuthority({
        canonicalBoardRuntime: board.value,
        initializationMode: input.initializationMode,
        operationOwner: input.operationOwner,
        runtimeBuildAuthorityBinding: input.runtimeBuildAuthorityBinding,
    });
    liveAuthorities.add(authority);
    return authority;
};

const crashAuthority = async (
    opened: OpenedOperationOwner,
    authority: BrowserFoundationAuthority,
): Promise<void> => {
    liveAuthorities.delete(authority);
    liveWorkers.delete(opened.worker);
    opened.worker.terminate();
    await waitForExclusiveLockRelease(opened.databaseName);
};

const closeAuthority = async (
    opened: OpenedOperationOwner,
    authority: BrowserFoundationAuthority,
): Promise<void> => {
    liveAuthorities.delete(authority);
    try {
        await authority.close();
    } finally {
        liveWorkers.delete(opened.worker);
        opened.worker.terminate();
        await waitForExclusiveLockRelease(opened.databaseName);
    }
};

const openParticipantAuthority = async (input: {
    canonicalBoardContext: CanonicalBoardContextInput;
    databaseName: string;
    expectedSnapshot?: BrowserDeviceWrappingSnapshot;
    orderedRosterParticipantIdentities: readonly Uint8Array[];
    rosterPosition: number;
    runtimeBuildAuthorityBinding: RuntimeBuildAuthorityBinding;
    runtimeBuildManifestHash: Uint8Array;
}): Promise<OpenedParticipantAuthority> => {
    const participantIdentity =
        input.orderedRosterParticipantIdentities[input.rosterPosition];
    if (participantIdentity === undefined) {
        throw new Error('The requested roster participant is unavailable.');
    }
    const opening = await openOperationOwner({
        binding: {
            actionContextHash:
                input.canonicalBoardContext.expectedActionContextHash.slice(),
            ceremonyContextHash:
                input.canonicalBoardContext.expectedCeremonyContextHash.slice(),
            participantId: participantIdentity.slice(),
            suiteId:
                input.canonicalBoardContext.expectedSuiteIdentifier.slice(),
        },
        databaseName: input.databaseName,
        mode:
            input.expectedSnapshot === undefined
                ? { kind: 'fresh' }
                : {
                      expectedSnapshot: input.expectedSnapshot,
                      kind: 'recovered',
                  },
        rosterPosition: input.rosterPosition,
        runtimeBuildManifestHash: input.runtimeBuildManifestHash,
    });
    const authority = await openAuthority({
        canonicalBoardContext: input.canonicalBoardContext,
        initializationMode:
            input.expectedSnapshot === undefined ? 'fresh' : 'recovered',
        operationOwner: opening.operationOwner,
        runtimeBuildAuthorityBinding: input.runtimeBuildAuthorityBinding,
    });
    const startupState = await authority.startup();
    if (startupState !== 'active') {
        throw new Error(
            `Roster position ${String(input.rosterPosition)} did not activate its browser foundation authority.`,
        );
    }
    const capability = authority.activeCapability();
    return Object.freeze({
        actionRandomness: authority.actionRandomness(capability),
        authority,
        capability,
        opening,
        rosterPosition: input.rosterPosition,
    });
};

const findWitnessRoleForSubject = async (input: {
    authority: BrowserFoundationAuthority;
    subjectParticipantIdentity: Uint8Array;
}): Promise<BrowserFoundationWitnessRole> => {
    const roles = await input.authority.witnessRoles();
    let matchingRole: BrowserFoundationWitnessRole | undefined;
    for (const role of roles) {
        const description =
            await input.authority.copyWitnessRoleDescription(role);
        if (
            bytesEqual(
                description.subjectParticipantIdentity,
                input.subjectParticipantIdentity,
            )
        ) {
            if (matchingRole !== undefined) {
                throw new Error(
                    'The fixed roster exposed duplicate witness roles for one subject.',
                );
            }
            matchingRole = role;
        }
    }
    if (matchingRole === undefined) {
        throw new Error(
            'The fixed roster does not expose the requested witness role.',
        );
    }
    return matchingRole;
};

const expectFreshOpeningToRefuseRetiredParticipant = async (input: {
    binding: Readonly<{
        actionContextHash: Uint8Array;
        ceremonyContextHash: Uint8Array;
        participantId: Uint8Array;
        suiteId: Uint8Array;
    }>;
    databaseName: string;
    rosterPosition: number;
    runtimeBuildManifestHash: Uint8Array;
}): Promise<void> => {
    await expect(
        openOperationOwner({
            binding: input.binding,
            databaseName: input.databaseName,
            mode: { kind: 'fresh' },
            rosterPosition: input.rosterPosition,
            runtimeBuildManifestHash: input.runtimeBuildManifestHash,
        }),
    ).rejects.toMatchObject({ code: 'Unavailable' });
    await waitForExclusiveLockRelease(input.databaseName);
};

afterEach(async () => {
    for (const authority of [...liveAuthorities]) {
        try {
            await authority.close();
        } catch {
            // Workers are terminated below even when orderly cleanup fails.
        }
    }
    liveAuthorities.clear();
    for (const worker of liveWorkers) {
        worker.terminate();
    }
    liveWorkers.clear();
    for (const databaseName of databaseNames) {
        await waitForExclusiveLockRelease(databaseName);
        await deleteDatabase(databaseName);
    }
    databaseNames.clear();
});

describe('Browser foundation authority real-component composition', () => {
    it('retires before exposing authority after an interrupted common-proof application handoff', async () => {
        const runtimeFixture =
            await activateRuntimeBuildAuthorityBindingFixture();
        const runtimeBindingDescription =
            copyRuntimeBuildAuthorityBindingDescription(
                runtimeFixture.activation.runtimeBuildAuthorityBinding,
            );
        const canonicalRosterBytes = createCanonicalRosterBytes();
        const canonicalBoardContext = createCanonicalBoardContextTestInput(
            await loadFreshTranscriptCoreKernel(),
            canonicalRosterBytes,
            runtimeFixture.canonicalSuiteRecordBytes,
        );
        const orderedRosterParticipantIdentities =
            copyAuthenticatedMailboxFrozenRosterParticipantIdentities(
                openAuthenticatedMailboxFrozenRoster(canonicalRosterBytes),
            );
        const participantIdentity = orderedRosterParticipantIdentities[0];
        if (participantIdentity === undefined) {
            throw new Error(
                'The canonical foundation roster does not contain its first participant.',
            );
        }
        const binding = Object.freeze({
            actionContextHash:
                canonicalBoardContext.expectedActionContextHash.slice(),
            ceremonyContextHash:
                canonicalBoardContext.expectedCeremonyContextHash.slice(),
            participantId: participantIdentity.slice(),
            suiteId: canonicalBoardContext.expectedSuiteIdentifier.slice(),
        });
        const databaseName = createDatabaseName();
        const deviceWrappingSnapshot =
            await createInterruptedCommonProofApplicationHandoff({
                binding,
                databaseName,
                runtimeBuildManifestHash:
                    runtimeBindingDescription.runtimeBuildManifestHash,
            });

        await expect(
            openOperationOwner({
                binding,
                databaseName,
                mode: {
                    expectedSnapshot: deviceWrappingSnapshot,
                    kind: 'recovered',
                },
                rosterPosition: 0,
                runtimeBuildManifestHash:
                    runtimeBindingDescription.runtimeBuildManifestHash,
            }),
        ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
        await waitForExclusiveLockRelease(databaseName);
        await expectFreshOpeningToRefuseRetiredParticipant({
            binding,
            databaseName,
            rosterPosition: 0,
            runtimeBuildManifestHash:
                runtimeBindingDescription.runtimeBuildManifestHash,
        });
    }, 60_000);

    it('retries a fail-once retirement write before recovered root opening releases ownership', async () => {
        const runtimeFixture =
            await activateRuntimeBuildAuthorityBindingFixture();
        const runtimeBindingDescription =
            copyRuntimeBuildAuthorityBindingDescription(
                runtimeFixture.activation.runtimeBuildAuthorityBinding,
            );
        const canonicalRosterBytes = createCanonicalRosterBytes();
        const canonicalBoardContext = createCanonicalBoardContextTestInput(
            await loadFreshTranscriptCoreKernel(),
            canonicalRosterBytes,
            runtimeFixture.canonicalSuiteRecordBytes,
        );
        const orderedRosterParticipantIdentities =
            copyAuthenticatedMailboxFrozenRosterParticipantIdentities(
                openAuthenticatedMailboxFrozenRoster(canonicalRosterBytes),
            );
        const participantIdentity = orderedRosterParticipantIdentities[0];
        if (participantIdentity === undefined) {
            throw new Error(
                'The canonical foundation roster does not contain its first participant.',
            );
        }
        const databaseName = createDatabaseName();
        const freshParticipant = await openParticipantAuthority({
            canonicalBoardContext,
            databaseName,
            orderedRosterParticipantIdentities,
            rosterPosition: 0,
            runtimeBuildAuthorityBinding:
                runtimeFixture.activation.runtimeBuildAuthorityBinding,
            runtimeBuildManifestHash:
                runtimeBindingDescription.runtimeBuildManifestHash,
        });
        await crashAuthority(
            freshParticipant.opening,
            freshParticipant.authority,
        );
        await deleteDeviceWrappingState(databaseName);

        const binding = Object.freeze({
            actionContextHash:
                canonicalBoardContext.expectedActionContextHash.slice(),
            ceremonyContextHash:
                canonicalBoardContext.expectedCeremonyContextHash.slice(),
            participantId: participantIdentity.slice(),
            suiteId: canonicalBoardContext.expectedSuiteIdentifier.slice(),
        });
        await expect(
            openOperationOwner({
                binding,
                databaseName,
                failFirstRetirementWrite: true,
                mode: {
                    expectedSnapshot:
                        freshParticipant.opening.deviceWrappingSnapshot,
                    kind: 'recovered',
                },
                rosterPosition: 0,
                runtimeBuildManifestHash:
                    runtimeBindingDescription.runtimeBuildManifestHash,
            }),
        ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
        await waitForExclusiveLockRelease(databaseName);
        await expectFreshOpeningToRefuseRetiredParticipant({
            binding,
            databaseName,
            rosterPosition: 0,
            runtimeBuildManifestHash:
                runtimeBindingDescription.runtimeBuildManifestHash,
        });
    }, 60_000);

    it('continues one fixed-roster foundation operation exactly and retires unavailable local state', async () => {
        const runtimeFixture =
            await activateRuntimeBuildAuthorityBindingFixture();
        const runtimeBindingDescription =
            copyRuntimeBuildAuthorityBindingDescription(
                runtimeFixture.activation.runtimeBuildAuthorityBinding,
            );
        const canonicalRosterBytes = createCanonicalRosterBytes();
        const canonicalBoardContext = createCanonicalBoardContextTestInput(
            await loadFreshTranscriptCoreKernel(),
            canonicalRosterBytes,
            runtimeFixture.canonicalSuiteRecordBytes,
        );
        const orderedRosterParticipantIdentities =
            copyAuthenticatedMailboxFrozenRosterParticipantIdentities(
                openAuthenticatedMailboxFrozenRoster(canonicalRosterBytes),
            );
        const subjectParticipantIdentity =
            orderedRosterParticipantIdentities[0];
        const firstWitnessParticipantIdentity =
            orderedRosterParticipantIdentities[1];
        if (
            subjectParticipantIdentity === undefined ||
            firstWitnessParticipantIdentity === undefined
        ) {
            throw new Error(
                'The canonical foundation roster does not contain its subject and first witness.',
            );
        }
        const stateVector = createStateVerifierTestVector({
            actionContextHash: canonicalBoardContext.expectedActionContextHash,
            ceremonyContextHash:
                canonicalBoardContext.expectedCeremonyContextHash,
            suiteIdentifier: canonicalBoardContext.expectedSuiteIdentifier,
        });
        expect(stateVector.canonicalRosterBytes).toEqual(canonicalRosterBytes);
        expect(stateVector.subjectParticipantIdentity).toEqual(
            subjectParticipantIdentity,
        );

        const freshParticipants = await Promise.all(
            Array.from(
                { length: requiredWitnessVoteCount + 1 },
                async (_unused, rosterPosition) =>
                    openParticipantAuthority({
                        canonicalBoardContext,
                        databaseName: createDatabaseName(),
                        orderedRosterParticipantIdentities,
                        rosterPosition,
                        runtimeBuildAuthorityBinding:
                            runtimeFixture.activation
                                .runtimeBuildAuthorityBinding,
                        runtimeBuildManifestHash:
                            runtimeBindingDescription.runtimeBuildManifestHash,
                    }),
            ),
        );
        const subject = freshParticipants[0];
        const firstWitness = freshParticipants[1];
        if (subject === undefined || firstWitness === undefined) {
            throw new Error(
                'The fixed-roster browser authority set is incomplete.',
            );
        }
        expect(await subject.authority.witnessRoles()).toHaveLength(
            foundationProfile.participantCount - 1,
        );
        const canonicalBoardSnapshot = requireValid(
            await subject.authority.ingestCanonicalBoard(subject.capability, [
                ...stateVector.reservationVoteCarriers
                    .slice()
                    .reverse()
                    .map((canonicalCarrier) => ({
                        canonicalCarrier: canonicalCarrier.slice(),
                    })),
                {
                    canonicalCarrier:
                        stateVector.reservation.canonicalIntentCarrier.slice(),
                },
            ]),
            'Canonical-board ingestion',
        );
        const canonicalBoardObjects = requireValid(
            await subject.authority.listCanonicalBoardObjects(
                subject.capability,
                canonicalBoardSnapshot,
            ),
            'Canonical-board object listing',
        );
        expect(canonicalBoardObjects).toHaveLength(
            requiredWitnessVoteCount + 1,
        );
        expect(
            canonicalBoardObjects.every(
                (verifiedObject) =>
                    Reflect.ownKeys(verifiedObject as object).length === 0,
            ),
        ).toBe(true);

        const producedIntent = requireValid(
            await subject.authority.produceActionRandomnessReservationIntent(
                subject.capability,
                subject.actionRandomness,
            ),
            'Action-randomness reservation intent production',
        );
        const originalIntentCarrier =
            producedIntent.canonicalReservationIntentCarrier.slice();
        const witnessVotes = await Promise.all(
            freshParticipants.slice(1).map(async (participant) => {
                const role = await findWitnessRoleForSubject({
                    authority: participant.authority,
                    subjectParticipantIdentity,
                });
                const canonicalVoteCarrier = requireValid(
                    await participant.authority.voteForActionRandomnessReservationIntent(
                        participant.capability,
                        role,
                        originalIntentCarrier,
                    ),
                    `Roster position ${String(participant.rosterPosition)} witness vote`,
                );
                return Object.freeze({
                    canonicalVoteCarrier: canonicalVoteCarrier.slice(),
                    participant,
                    role,
                });
            }),
        );
        expect(witnessVotes).toHaveLength(requiredWitnessVoteCount);
        expect(
            new Set(
                witnessVotes.map(({ canonicalVoteCarrier }) =>
                    bytesToHex(canonicalVoteCarrier),
                ),
            ).size,
        ).toBe(requiredWitnessVoteCount);

        const certifiedReservation = requireValid(
            await subject.authority.certifyActionRandomnessReservation(
                subject.capability,
                producedIntent.stateReservationIntent,
                witnessVotes.map(({ canonicalVoteCarrier }) =>
                    canonicalVoteCarrier.slice(),
                ),
            ),
            'Seven-vote action-randomness reservation certification',
        );
        const originalStateCertificate =
            certifiedReservation.canonicalStateCertificate.slice();
        await subject.authority.releaseStateReservation(
            subject.capability,
            certifiedReservation.stateReservation,
        );

        const targetReservationInput = Object.freeze({
            canonicalReservationIntentCarrier:
                stateVector.reservation.canonicalIntentCarrier,
            canonicalStateCertificate:
                stateVector.reservation.canonicalStateCertificate,
            capabilityKind: stateCapabilityKinds.targetRelease,
            expectedAuthorizationHash: stateVector.authorizationHash,
            subjectParticipantIdentity: stateVector.subjectParticipantIdentity,
        });
        const targetReservation = requireValid(
            await subject.authority.verifyStateReservation(
                subject.capability,
                targetReservationInput,
            ),
            'Target reservation verification',
        );
        const targetProofAttempt =
            await subject.authority.deriveTargetReleaseAttempt(
                subject.capability,
                subject.actionRandomness,
                targetReservation,
                { rosterPosition: subject.rosterPosition },
            );
        const originalProofAttemptBinding =
            await subject.authority.copyProofAttemptBinding(
                subject.capability,
                targetProofAttempt,
            );

        const firstWitnessVote = witnessVotes[0];
        const targetWitnessVoteCarrier = stateVector.reservationVoteCarriers[0];
        if (
            firstWitnessVote === undefined ||
            targetWitnessVoteCarrier === undefined
        ) {
            throw new Error('The first fixed-roster witness vote is missing.');
        }
        const witnessTargetReservation = requireValid(
            await firstWitness.authority.verifyStateReservation(
                firstWitness.capability,
                targetReservationInput,
            ),
            'Witness target reservation verification',
        );
        const witnessTargetBinding =
            await firstWitness.authority.openWitnessStateReservationBinding(
                firstWitness.capability,
                firstWitnessVote.role,
                witnessTargetReservation,
            );
        await firstWitness.authority.compareAndLockWitnessIntent(
            firstWitness.capability,
            firstWitnessVote.role,
            { durableBinding: witnessTargetBinding },
        );
        await expect(
            firstWitness.authority.readWitnessSignedVoteCarrier(
                firstWitness.capability,
                firstWitnessVote.role,
                { durableBinding: witnessTargetBinding },
            ),
        ).rejects.toMatchObject({ code: 'MissingRecord' });
        expect(firstWitness.authority.state()).toBe('active');
        expect(
            await firstWitness.authority.cacheWitnessSignedVoteCarrier(
                firstWitness.capability,
                firstWitnessVote.role,
                {
                    canonicalSignedVoteCarrier: targetWitnessVoteCarrier,
                    durableBinding: witnessTargetBinding,
                },
            ),
        ).toEqual(targetWitnessVoteCarrier);
        expect(
            await firstWitness.authority.readWitnessSignedVoteCarrier(
                firstWitness.capability,
                firstWitnessVote.role,
                { durableBinding: witnessTargetBinding },
            ),
        ).toEqual(targetWitnessVoteCarrier);
        await firstWitness.authority.closeWitnessDurableStateBinding(
            firstWitness.capability,
            witnessTargetBinding,
        );
        await firstWitness.authority.releaseStateReservation(
            firstWitness.capability,
            witnessTargetReservation,
        );

        await Promise.all(
            freshParticipants
                .slice(2)
                .map((participant) =>
                    closeAuthority(participant.opening, participant.authority),
                ),
        );
        await crashAuthority(subject.opening, subject.authority);
        await crashAuthority(firstWitness.opening, firstWitness.authority);

        const recoveredSubject = await openParticipantAuthority({
            canonicalBoardContext,
            databaseName: subject.opening.databaseName,
            expectedSnapshot: subject.opening.deviceWrappingSnapshot,
            orderedRosterParticipantIdentities,
            rosterPosition: subject.rosterPosition,
            runtimeBuildAuthorityBinding:
                runtimeFixture.activation.runtimeBuildAuthorityBinding,
            runtimeBuildManifestHash:
                runtimeBindingDescription.runtimeBuildManifestHash,
        });
        const recoveredWitness = await openParticipantAuthority({
            canonicalBoardContext,
            databaseName: firstWitness.opening.databaseName,
            expectedSnapshot: firstWitness.opening.deviceWrappingSnapshot,
            orderedRosterParticipantIdentities,
            rosterPosition: firstWitness.rosterPosition,
            runtimeBuildAuthorityBinding:
                runtimeFixture.activation.runtimeBuildAuthorityBinding,
            runtimeBuildManifestHash:
                runtimeBindingDescription.runtimeBuildManifestHash,
        });

        expect(recoveredSubject.opening.deviceWrappingSnapshot).toEqual(
            subject.opening.deviceWrappingSnapshot,
        );
        expect(recoveredWitness.opening.deviceWrappingSnapshot).toEqual(
            firstWitness.opening.deviceWrappingSnapshot,
        );
        const recoveredIntent = requireValid(
            await recoveredSubject.authority.produceActionRandomnessReservationIntent(
                recoveredSubject.capability,
                recoveredSubject.actionRandomness,
            ),
            'Recovered action-randomness reservation intent production',
        );
        expect(recoveredIntent.canonicalReservationIntentCarrier).toEqual(
            originalIntentCarrier,
        );
        const recoveredWitnessRole = await findWitnessRoleForSubject({
            authority: recoveredWitness.authority,
            subjectParticipantIdentity,
        });
        const recoveredWitnessVote = requireValid(
            await recoveredWitness.authority.voteForActionRandomnessReservationIntent(
                recoveredWitness.capability,
                recoveredWitnessRole,
                recoveredIntent.canonicalReservationIntentCarrier,
            ),
            'Recovered fixed-roster witness vote',
        );
        expect(recoveredWitnessVote).toEqual(
            firstWitnessVote.canonicalVoteCarrier,
        );
        const recoveredVoteCarriers = witnessVotes.map(
            ({ canonicalVoteCarrier }, voteIndex) =>
                voteIndex === 0
                    ? recoveredWitnessVote.slice()
                    : canonicalVoteCarrier.slice(),
        );
        const recoveredCertifiedReservation = requireValid(
            await recoveredSubject.authority.certifyActionRandomnessReservation(
                recoveredSubject.capability,
                recoveredIntent.stateReservationIntent,
                recoveredVoteCarriers,
            ),
            'Recovered seven-vote action-randomness reservation certification',
        );
        expect(recoveredCertifiedReservation.canonicalStateCertificate).toEqual(
            originalStateCertificate,
        );
        await recoveredSubject.authority.releaseStateReservation(
            recoveredSubject.capability,
            recoveredCertifiedReservation.stateReservation,
        );

        const recoveredTargetReservation = requireValid(
            await recoveredSubject.authority.verifyStateReservation(
                recoveredSubject.capability,
                targetReservationInput,
            ),
            'Recovered target reservation verification',
        );
        const recoveredProofAttempt =
            await recoveredSubject.authority.deriveTargetReleaseAttempt(
                recoveredSubject.capability,
                recoveredSubject.actionRandomness,
                recoveredTargetReservation,
                { rosterPosition: recoveredSubject.rosterPosition },
            );
        expect(
            await recoveredSubject.authority.copyProofAttemptBinding(
                recoveredSubject.capability,
                recoveredProofAttempt,
            ),
        ).toEqual(originalProofAttemptBinding);

        const recoveredWitnessTargetReservation = requireValid(
            await recoveredWitness.authority.verifyStateReservation(
                recoveredWitness.capability,
                targetReservationInput,
            ),
            'Recovered witness target reservation verification',
        );
        const recoveredWitnessTargetBinding =
            await recoveredWitness.authority.openWitnessStateReservationBinding(
                recoveredWitness.capability,
                recoveredWitnessRole,
                recoveredWitnessTargetReservation,
            );
        expect(
            await recoveredWitness.authority.readWitnessSignedVoteCarrier(
                recoveredWitness.capability,
                recoveredWitnessRole,
                { durableBinding: recoveredWitnessTargetBinding },
            ),
        ).toEqual(targetWitnessVoteCarrier);

        await tamperAuthenticatedSignedVoteRecords(
            recoveredWitness.opening.databaseName,
        );
        await expect(
            recoveredWitness.authority.readWitnessSignedVoteCarrier(
                recoveredWitness.capability,
                recoveredWitnessRole,
                { durableBinding: recoveredWitnessTargetBinding },
            ),
        ).rejects.toMatchObject({ code: 'RecordAuthenticationFailed' });
        expect(recoveredWitness.authority.state()).toBe('retired');
        expect(recoveredWitness.authority.retirementReason()).toBe(
            'witnessStateUnavailable',
        );
        await closeAuthority(
            recoveredWitness.opening,
            recoveredWitness.authority,
        );
        await expectFreshOpeningToRefuseRetiredParticipant({
            binding: {
                actionContextHash:
                    canonicalBoardContext.expectedActionContextHash,
                ceremonyContextHash:
                    canonicalBoardContext.expectedCeremonyContextHash,
                participantId: firstWitnessParticipantIdentity,
                suiteId: canonicalBoardContext.expectedSuiteIdentifier,
            },
            databaseName: recoveredWitness.opening.databaseName,
            rosterPosition: recoveredWitness.rosterPosition,
            runtimeBuildManifestHash:
                runtimeBindingDescription.runtimeBuildManifestHash,
        });

        await crashAuthority(
            recoveredSubject.opening,
            recoveredSubject.authority,
        );
        await deleteDeviceWrappingState(recoveredSubject.opening.databaseName);
        const subjectBinding = Object.freeze({
            actionContextHash:
                canonicalBoardContext.expectedActionContextHash.slice(),
            ceremonyContextHash:
                canonicalBoardContext.expectedCeremonyContextHash.slice(),
            participantId: subjectParticipantIdentity.slice(),
            suiteId: canonicalBoardContext.expectedSuiteIdentifier.slice(),
        });
        await expect(
            openOperationOwner({
                binding: subjectBinding,
                databaseName: recoveredSubject.opening.databaseName,
                mode: {
                    expectedSnapshot:
                        recoveredSubject.opening.deviceWrappingSnapshot,
                    kind: 'recovered',
                },
                rosterPosition: recoveredSubject.rosterPosition,
                runtimeBuildManifestHash:
                    runtimeBindingDescription.runtimeBuildManifestHash,
            }),
        ).rejects.toMatchObject({ code: 'Unavailable' });
        await waitForExclusiveLockRelease(
            recoveredSubject.opening.databaseName,
        );
        await expectFreshOpeningToRefuseRetiredParticipant({
            binding: subjectBinding,
            databaseName: recoveredSubject.opening.databaseName,
            rosterPosition: recoveredSubject.rosterPosition,
            runtimeBuildManifestHash:
                runtimeBindingDescription.runtimeBuildManifestHash,
        });
    }, 120_000);
});
