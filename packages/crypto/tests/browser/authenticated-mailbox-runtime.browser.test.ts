import { afterEach, describe, expect, it } from 'vitest';

type CompletedResult = Readonly<{
    carrierByteLength: number;
    ciphertextChunkCount: number;
    malformedCiphertextPullCount: number;
    malformedDownstreamCount: number;
    malformedRefusalReason?: string;
    messageKind: 'completed';
    plaintextMatches: boolean;
    requestIdentifier: number;
    roundTripDisposition?: string;
    roundTripRefusalReason?: string;
    successfulDownstreamCount: number;
    wrongContextCiphertextPullCount: number;
    wrongContextDownstreamCount: number;
    wrongContextRefusalReason?: string;
}>;

type FailedResult = Readonly<{
    failureMessage?: string;
    failureName?: string;
    messageKind: 'failed';
    requestIdentifier: number;
}>;

const workers = new Set<Worker>();

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const isWorkerResult = (
    value: unknown,
): value is CompletedResult | FailedResult =>
    isPlainRecord(value) &&
    (value.messageKind === 'completed' || value.messageKind === 'failed') &&
    Number.isSafeInteger(value.requestIdentifier);

const runMailboxWorker = (): Promise<CompletedResult> => {
    const worker = new Worker(
        new URL(
            '../support/authenticated-mailbox-browser-worker.ts',
            import.meta.url,
        ),
        { type: 'module' },
    );
    workers.add(worker);
    const requestIdentifier = 1;

    return new Promise<CompletedResult>((resolve, reject) => {
        worker.addEventListener(
            'error',
            (event) =>
                reject(
                    event.error instanceof Error
                        ? event.error
                        : new Error('The authenticated mailbox worker failed.'),
                ),
            { once: true },
        );
        worker.addEventListener(
            'messageerror',
            () =>
                reject(
                    new Error(
                        'The authenticated mailbox worker response could not be cloned.',
                    ),
                ),
            { once: true },
        );
        worker.addEventListener('message', (event) => {
            const result = event.data as unknown;
            if (
                !isWorkerResult(result) ||
                result.requestIdentifier !== requestIdentifier
            ) {
                reject(
                    new Error(
                        'The authenticated mailbox worker returned a malformed result.',
                    ),
                );
                return;
            }
            if (result.messageKind === 'failed') {
                reject(
                    new Error(
                        `${result.failureName ?? 'WorkerError'}: ${result.failureMessage ?? 'The authenticated mailbox worker failed.'}`,
                    ),
                );
                return;
            }
            resolve(result);
        });
        worker.postMessage({
            command: 'run',
            requestIdentifier,
        });
    }).finally(() => {
        worker.terminate();
        workers.delete(worker);
    });
};

afterEach(() => {
    for (const worker of workers) {
        worker.terminate();
    }
    workers.clear();
});

describe('Authenticated mailbox runtime in a browser worker', () => {
    it('round trips a canonical signed carrier and refuses malformed or wrong-context ingress before ciphertext fetch', async () => {
        const result = await runMailboxWorker();

        expect(result).toMatchObject({
            ciphertextChunkCount: 1,
            malformedCiphertextPullCount: 0,
            malformedDownstreamCount: 0,
            malformedRefusalReason: 'malformedEncoding',
            messageKind: 'completed',
            plaintextMatches: true,
            roundTripDisposition: 'accepted',
            roundTripRefusalReason: undefined,
            successfulDownstreamCount: 3,
            wrongContextCiphertextPullCount: 0,
            wrongContextDownstreamCount: 0,
            wrongContextRefusalReason: 'wrongContext',
        });
        expect(result.carrierByteLength).toBeGreaterThan(0);
    });
});
