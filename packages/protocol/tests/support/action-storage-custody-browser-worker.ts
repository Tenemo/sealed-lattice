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
    workerKernel: new TestActionStorageWorkerKernel({
        actionStorageRoot: createTestBytes(testActionStorageRootByteLength, 29),
        cryptoProvider: crypto,
    }),
    workerScope,
});
