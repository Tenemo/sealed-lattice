import {
    foundationProfile,
    type BrowserActionStorageRootBinding,
} from '@sealed-lattice/types';

import { persistCommonProofApplicationAuthorization } from '#packages/protocol/src/runtime/durable-state-witness-service';
import { openWebLockOwnedBrowserActionStorageCustody } from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import {
    createTestBytes,
    TestActionStorageWorkerKernel,
    testActionStorageRootByteLength,
} from '#packages/protocol/tests/support/action-storage-custody-test-support';

const workerScope = globalThis as unknown as Readonly<{
    addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
    postMessage(message: unknown): void;
}>;

const transactionLimits = {
    maximumActiveTransactionCount: 2,
    maximumLeaseByteLength: 65_536,
    maximumLeaseCountPerTransaction: 32,
    maximumOwnedRecordCount: 256,
    maximumStoredValueByteLength: 4_194_304,
    maximumTransactionByteLength: 1_048_576,
    maximumTransactionLifetimeMilliseconds: 10_000,
} as const;
const maximumConfiguredWitnessPayloadByteLength = 61_440;
const runtimeBuildManifestHash = createTestBytes(64, 83);
const testBinding: BrowserActionStorageRootBinding = Object.freeze({
    actionContextHash: createTestBytes(64, 41),
    ceremonyContextHash: createTestBytes(64, 23),
    participantId: createTestBytes(64, 59),
    suiteId: createTestBytes(64, 7),
});

const runBoundaryTest = async (databaseName: string): Promise<void> => {
    const ownedStorage = await openWebLockOwnedBrowserActionStorageCustody({
        acquisitionDeadlineEpochMilliseconds: undefined,
        binding: testBinding,
        cryptoProvider: crypto,
        databaseName,
        indexedDbFactory: indexedDB,
        keyRangeFactory: IDBKeyRange,
        limits: transactionLimits,
        lockManager: navigator.locks,
        namespace: 'foundation-witness-boundary',
        runtimeBuildManifestHash,
        workerKernel: new TestActionStorageWorkerKernel({
            actionStorageRoot: createTestBytes(
                testActionStorageRootByteLength,
                29,
            ),
            cryptoProvider: crypto,
        }),
    });
    try {
        const snapshot = await ownedStorage.custody.initialize();
        await ownedStorage.openRootAndAuthenticatedStore({
            expectedSnapshot: snapshot,
            untrustedExpectedCommitment: {
                storageRootCommitment: snapshot.storageRootCommitment.slice(),
            },
        });
        const committed =
            await ownedStorage.commitFreshFoundationInitialization({
                actionRandomnessRecordContext: { recordVersion: 0n },
                orderedWitnessBindings: Array.from(
                    { length: foundationProfile.participantCount - 1 },
                    (_unused, witnessIndex) => ({
                        subjectParticipantIdentity: createTestBytes(
                            64,
                            101 + witnessIndex,
                        ),
                        witnessParticipantIdentity:
                            testBinding.participantId.slice(),
                    }),
                ),
                runtimeBuildManifestHash,
            });
        const witnessRecord = committed.orderedWitnessRecords[0];
        if (witnessRecord === undefined) {
            throw new Error(
                'The foundation witness boundary test has no role.',
            );
        }

        let oversizedFailureCode: unknown;
        try {
            await ownedStorage.openFoundationWitnessRole({
                durableStateLimits: {
                    maximumExactOutputByteLength:
                        maximumConfiguredWitnessPayloadByteLength + 1,
                    maximumRecordSealingCount: 128,
                    maximumSignedVoteCarrierByteLength:
                        maximumConfiguredWitnessPayloadByteLength,
                    transactionLifetimeMilliseconds: 10_000,
                },
                openingMode: 'fresh-provisioned',
                record: witnessRecord,
            });
        } catch (error) {
            oversizedFailureCode =
                error instanceof Error && 'code' in error
                    ? (error as { code?: unknown }).code
                    : undefined;
        }
        if (oversizedFailureCode !== 'OpenFailed') {
            throw new Error(
                'The root-backed witness role accepted an oversized durable payload profile.',
            );
        }

        const openedRole = await ownedStorage.openFoundationWitnessRole({
            durableStateLimits: {
                maximumExactOutputByteLength:
                    maximumConfiguredWitnessPayloadByteLength,
                maximumRecordSealingCount: 128,
                maximumSignedVoteCarrierByteLength:
                    maximumConfiguredWitnessPayloadByteLength,
                transactionLifetimeMilliseconds: 10_000,
            },
            openingMode: 'fresh-provisioned',
            record: witnessRecord,
        });
        const service = openedRole.durableStateService.claimExclusiveOwner();
        try {
            const authorizationFrame = createTestBytes(742, 131);
            const proofApplicationSlotHash = createTestBytes(64, 149);
            let malformedAttemptFailed = false;
            try {
                await persistCommonProofApplicationAuthorization(service, {
                    authorizationFrame,
                    onPublicationDisposition: () => undefined,
                    proofApplicationSlotHash:
                        proofApplicationSlotHash.subarray(1),
                });
            } catch {
                malformedAttemptFailed = true;
            }
            if (!malformedAttemptFailed) {
                throw new Error(
                    'The malformed pre-publication application did not fail.',
                );
            }

            const retryPublicationDispositions: string[] = [];
            const authenticatedFrame =
                await persistCommonProofApplicationAuthorization(service, {
                    authorizationFrame,
                    onPublicationDisposition: (disposition) => {
                        retryPublicationDispositions.push(disposition);
                    },
                    proofApplicationSlotHash,
                });
            if (
                retryPublicationDispositions.length !== 1 ||
                retryPublicationDispositions[0] !==
                    'published-or-indeterminate' ||
                authenticatedFrame.byteLength !==
                    authorizationFrame.byteLength ||
                authenticatedFrame.some(
                    (byte, byteIndex) => byte !== authorizationFrame[byteIndex],
                )
            ) {
                throw new Error(
                    'The retry did not commit and reread the exact authenticated authorization frame.',
                );
            }
            authenticatedFrame.fill(0);
            authorizationFrame.fill(0);
            proofApplicationSlotHash.fill(0);
        } finally {
            await service.close();
        }
    } finally {
        await ownedStorage.close();
    }
};

workerScope.addEventListener('message', (event) => {
    const data = event.data as { databaseName?: unknown };
    if (typeof data?.databaseName !== 'string') {
        workerScope.postMessage({
            error: 'The boundary test requires a database name.',
            success: false,
        });
        return;
    }
    void runBoundaryTest(data.databaseName).then(
        () => workerScope.postMessage({ success: true }),
        (error: unknown) =>
            workerScope.postMessage({
                error: error instanceof Error ? error.message : String(error),
                success: false,
            }),
    );
});
