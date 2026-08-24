import { installBrowserActionStorageCustodyWorkerHost } from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';
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
    removeEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
}>;

installBrowserActionStorageCustodyWorkerHost({
    checkpointStore: {
        boundaryPolicy: {
            validatePublication: () => undefined,
            validateResume: () => undefined,
        },
        limits: {
            maximumActiveOperationIdentityCount: 64,
            maximumCheckpointStateByteLength: 1_048_576,
            maximumManifestByteLength: 65_536,
            maximumRandomCursorManifestByteLength: 1_048_576,
            maximumRecordSealingCount: 4_096,
            maximumSourceDigestCount: 32,
            transactionLifetimeMilliseconds: 10_000,
        },
    },
    foundationWitnessRuntime: {
        durableStateLimits: {
            maximumExactOutputByteLength: 61_440,
            maximumRecordSealingCount: 128,
            maximumSignedVoteCarrierByteLength: 61_440,
            transactionLifetimeMilliseconds: 10_000,
        },
        openWitnessCryptography: () => ({
            stateObjectSignatureOperation: {
                signStateObjectMessage: () => {
                    throw new Error(
                        'The custody lifecycle test does not sign foundation state objects.',
                    );
                },
            },
        }),
    },
    workerKernel: new TestActionStorageWorkerKernel({
        actionStorageRoot: createTestBytes(testActionStorageRootByteLength, 29),
        cryptoProvider: crypto,
    }),
    workerScope,
});
