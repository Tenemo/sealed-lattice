import {
    CanonicalStreamCancellationError,
    CanonicalStreamRefusalError,
    CanonicalStreamResourceError,
    openCanonicalStreamWorkerRuntime,
    type CanonicalStreamDomain,
} from '#packages/wasm/src/canonical-stream-runtime';
import { loadFreshTranscriptCoreKernel } from '#packages/wasm/src/index';

type StartMessage = Readonly<{
    cancelAfterFirstChunk: boolean;
    command: 'start';
    requestIdentifier: number;
    streamDomain: number;
    totalByteLength: number;
}>;

type ChunkMessage = Readonly<{
    buffer?: ArrayBuffer;
    chunkIndex: number;
    messageKind: 'chunk' | 'end';
    phase: 'read' | 'write';
    requestIdentifier: number;
}>;

type PendingPull = Readonly<{
    chunkIndex: number;
    phase: 'read' | 'write';
    reject(failure: unknown): void;
    resolve(bytes: ArrayBuffer | undefined): void;
}>;

const workerScope = globalThis as unknown as Readonly<{
    addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
    postMessage(message: unknown): void;
}>;

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const isStartMessage = (value: unknown): value is StartMessage =>
    isPlainRecord(value) &&
    value.command === 'start' &&
    Number.isSafeInteger(value.requestIdentifier) &&
    Number.isSafeInteger(value.streamDomain) &&
    Number.isSafeInteger(value.totalByteLength) &&
    typeof value.cancelAfterFirstChunk === 'boolean';

const isChunkMessage = (value: unknown): value is ChunkMessage =>
    isPlainRecord(value) &&
    (value.messageKind === 'chunk' || value.messageKind === 'end') &&
    (value.phase === 'read' || value.phase === 'write') &&
    Number.isSafeInteger(value.requestIdentifier) &&
    Number.isSafeInteger(value.chunkIndex) &&
    (value.messageKind === 'end' ||
        Object.prototype.toString.call(value.buffer) ===
            '[object ArrayBuffer]');

let activeRequestIdentifier: number | undefined;
let pendingPull: PendingPull | undefined;

const failPendingPull = (failure: unknown): void => {
    const pending = pendingPull;
    pendingPull = undefined;
    pending?.reject(failure);
};

const pullChunk = (
    requestIdentifier: number,
    phase: 'read' | 'write',
    chunkIndex: number,
    expectedByteLength: number,
): Promise<ArrayBuffer | undefined> => {
    if (pendingPull !== undefined) {
        throw new Error(
            'The stream worker attempted to prefetch a payload chunk.',
        );
    }
    return new Promise<ArrayBuffer | undefined>((resolve, reject) => {
        pendingPull = { chunkIndex, phase, reject, resolve };
        workerScope.postMessage({
            chunkIndex,
            expectedByteLength,
            messageKind: 'pull',
            phase,
            requestIdentifier,
        });
    });
};

const run = async (message: StartMessage): Promise<void> => {
    if (activeRequestIdentifier !== undefined) {
        throw new Error('The stream worker accepts only one active operation.');
    }
    activeRequestIdentifier = message.requestIdentifier;
    const kernel = await loadFreshTranscriptCoreKernel();
    const runtime = openCanonicalStreamWorkerRuntime({ kernel });
    const abortController = new AbortController();
    let consumedByteLength = 0;
    try {
        const descriptorBytes = await runtime.write({
            abortSignal: abortController.signal,
            emitChunk: ({ chunkIndex }) => {
                if (message.cancelAfterFirstChunk && chunkIndex === 0) {
                    abortController.abort();
                }
                return Promise.resolve();
            },
            pullChunk: async ({ chunkIndex, expectedByteLength }) =>
                pullChunk(
                    message.requestIdentifier,
                    'write',
                    chunkIndex,
                    expectedByteLength,
                ),
            streamDomain: message.streamDomain as CanonicalStreamDomain,
            totalByteLength: message.totalByteLength,
        });
        await runtime.read({
            abortSignal: abortController.signal,
            consumeVerifiedChunk: ({ bytes }) => {
                consumedByteLength += bytes.byteLength;
                return Promise.resolve();
            },
            descriptorBytes,
            pullChunk: async ({ chunkIndex, expectedByteLength }) =>
                pullChunk(
                    message.requestIdentifier,
                    'read',
                    chunkIndex,
                    expectedByteLength,
                ),
            streamDomain: message.streamDomain as CanonicalStreamDomain,
        });
        workerScope.postMessage({
            consumedByteLength,
            counters: runtime.counterSnapshot(),
            descriptorByteLength: descriptorBytes.byteLength,
            messageKind: 'completed',
            requestIdentifier: message.requestIdentifier,
        });
    } catch (error) {
        workerScope.postMessage({
            consumedByteLength,
            counters: runtime.counterSnapshot(),
            failureKind:
                error instanceof CanonicalStreamCancellationError
                    ? 'cancelled'
                    : error instanceof CanonicalStreamResourceError
                      ? 'resource'
                      : error instanceof CanonicalStreamRefusalError
                        ? 'refused'
                        : 'internal',
            messageKind: 'failed',
            refusalReason:
                error instanceof CanonicalStreamRefusalError
                    ? error.refusalReason
                    : undefined,
            requestIdentifier: message.requestIdentifier,
        });
    } finally {
        failPendingPull(new Error('The stream worker operation ended.'));
        activeRequestIdentifier = undefined;
    }
};

workerScope.addEventListener('message', (event) => {
    const message = event.data;
    if (isStartMessage(message)) {
        void run(message).catch(() => {
            workerScope.postMessage({
                failureKind: 'internal',
                messageKind: 'failed',
                requestIdentifier: message.requestIdentifier,
            });
        });
        return;
    }
    if (!isChunkMessage(message)) {
        failPendingPull(
            new Error('The stream worker received a malformed chunk response.'),
        );
        return;
    }
    const pending = pendingPull;
    pendingPull = undefined;
    if (
        pending === undefined ||
        message.requestIdentifier !== activeRequestIdentifier ||
        message.phase !== pending.phase ||
        message.chunkIndex !== pending.chunkIndex
    ) {
        pending?.reject(
            new Error(
                'The stream worker received a mismatched chunk response.',
            ),
        );
        return;
    }
    pending.resolve(message.messageKind === 'end' ? undefined : message.buffer);
});
