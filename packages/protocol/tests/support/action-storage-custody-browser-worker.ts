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

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const hexToBytes = (hex: string): Uint8Array =>
    Uint8Array.from({ length: hex.length / 2 }, (_unused, index) =>
        Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16),
    );

const cursorTextEncoder = new TextEncoder();
const cursorTextDecoder = new TextDecoder();

installBrowserActionStorageCustodyWorkerHost({
    checkpointStore: {
        boundaryPolicy: {
            validatePublication: () => undefined,
            validateResume: () => undefined,
        },
        cursorKernel: {
            decodePrivateRandomCursor: ({ canonicalBytesHex }) => {
                const bytes = hexToBytes(canonicalBytesHex);
                if (bytes[0] !== 0x04 || bytes[1] !== 0x18) {
                    throw new Error(
                        'Malformed checkpoint cursor test encoding.',
                    );
                }
                return {
                    value: JSON.parse(
                        cursorTextDecoder.decode(bytes.subarray(2)),
                    ) as {
                        derivationContextHash: string;
                        family: number;
                        nextCounter: string;
                        nextUnreadBitOffsetInBufferedBlock?: number;
                        purpose: number;
                        streamAttemptIdentifierHex: string;
                    },
                };
            },
            encodePrivateRandomCursor: (value) => ({
                canonicalBytesHex: bytesToHex(
                    Uint8Array.from([
                        0x04,
                        0x18,
                        ...cursorTextEncoder.encode(JSON.stringify(value)),
                    ]),
                ),
            }),
        },
        limits: {
            maximumCheckpointStateByteLength: 1_048_576,
            maximumManifestByteLength: 65_536,
            maximumRandomCursorCount: 32,
            maximumRecordSealingCount: 4_096,
            maximumSourceDigestCount: 32,
            maximumStreamAttemptCount: 32,
            transactionLifetimeMilliseconds: 10_000,
        },
    },
    foundationWitnessRuntime: {
        durableStateLimits: {
            maximumExactOutputByteLength: 65_536,
            maximumRecordSealingCount: 128,
            maximumSignedVoteCarrierByteLength: 65_536,
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
