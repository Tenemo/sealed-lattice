type PullMessage = Readonly<{
    chunkIndex: number;
    expectedByteLength: number;
    messageKind: 'pull';
    phase: 'read' | 'write';
    requestIdentifier: number;
}>;

type CanonicalStreamBrowserWorkerResult = Readonly<{
    consumedByteLength?: number;
    counters?: Readonly<Record<string, number>>;
    descriptorByteLength?: number;
    failureKind?: 'cancelled' | 'internal' | 'refused' | 'resource';
    messageKind: 'completed' | 'failed';
    refusalReason?: string;
    requestIdentifier: number;
}>;

type CanonicalStreamBrowserWorkerRun = Readonly<{
    maximumOutstandingPullCount: number;
    pullOrder: readonly string[];
    result: CanonicalStreamBrowserWorkerResult;
}>;

const workers = new Set<Worker>();

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const isPullMessage = (value: unknown): value is PullMessage =>
    isPlainRecord(value) &&
    value.messageKind === 'pull' &&
    (value.phase === 'read' || value.phase === 'write') &&
    Number.isSafeInteger(value.requestIdentifier) &&
    Number.isSafeInteger(value.chunkIndex) &&
    Number.isSafeInteger(value.expectedByteLength);

const isResultMessage = (
    value: unknown,
): value is CanonicalStreamBrowserWorkerResult =>
    isPlainRecord(value) &&
    (value.messageKind === 'completed' || value.messageKind === 'failed') &&
    Number.isSafeInteger(value.requestIdentifier);

const createChunk = (
    chunkIndex: number,
    byteLength: number,
    byteSeed: number,
    chunkIndexMultiplier: number,
): ArrayBuffer =>
    Uint8Array.from(
        { length: byteLength },
        (_, byteIndex) =>
            (byteSeed + chunkIndex * chunkIndexMultiplier + byteIndex * 131) &
            0xff,
    ).buffer;

export const runCanonicalStreamBrowserWorker = (input: {
    readonly byteSeed: number;
    readonly chunkIndexMultiplier: number;
    readonly operationName: string;
    readonly requestIdentifier: number;
    readonly startMessage: Readonly<Record<string, boolean | number | string>>;
}): Promise<CanonicalStreamBrowserWorkerRun> => {
    const worker = new Worker(
        new URL('./canonical-stream-browser-worker.ts', import.meta.url),
        { type: 'module' },
    );
    workers.add(worker);
    const pullOrder: string[] = [];
    let outstandingPullCount = 0;
    let maximumOutstandingPullCount = 0;

    return new Promise<CanonicalStreamBrowserWorkerRun>((resolve, reject) => {
        worker.addEventListener(
            'error',
            (event) =>
                reject(
                    event.error instanceof Error
                        ? event.error
                        : new Error(`${input.operationName} worker failed.`),
                ),
            { once: true },
        );
        worker.addEventListener('messageerror', () => {
            reject(
                new Error(
                    `${input.operationName} worker message could not be cloned.`,
                ),
            );
        });
        worker.addEventListener('message', (event) => {
            const message = event.data as unknown;
            if (isPullMessage(message)) {
                if (message.requestIdentifier !== input.requestIdentifier) {
                    reject(
                        new Error(
                            `${input.operationName} worker returned a mismatched request identifier.`,
                        ),
                    );
                    return;
                }
                outstandingPullCount += 1;
                maximumOutstandingPullCount = Math.max(
                    maximumOutstandingPullCount,
                    outstandingPullCount,
                );
                pullOrder.push(`${message.phase}:${message.chunkIndex}`);
                if (message.expectedByteLength === 0) {
                    worker.postMessage({
                        chunkIndex: message.chunkIndex,
                        messageKind: 'end',
                        phase: message.phase,
                        requestIdentifier: input.requestIdentifier,
                    });
                } else {
                    const buffer = createChunk(
                        message.chunkIndex,
                        message.expectedByteLength,
                        input.byteSeed,
                        input.chunkIndexMultiplier,
                    );
                    worker.postMessage(
                        {
                            buffer,
                            chunkIndex: message.chunkIndex,
                            messageKind: 'chunk',
                            phase: message.phase,
                            requestIdentifier: input.requestIdentifier,
                        },
                        [buffer],
                    );
                    if (buffer.byteLength !== 0) {
                        reject(
                            new Error(
                                `${input.operationName} worker chunk was not transferred.`,
                            ),
                        );
                        return;
                    }
                }
                outstandingPullCount -= 1;
                return;
            }
            if (
                !isResultMessage(message) ||
                message.requestIdentifier !== input.requestIdentifier
            ) {
                reject(
                    new Error(
                        `${input.operationName} worker returned malformed data.`,
                    ),
                );
                return;
            }
            resolve({
                maximumOutstandingPullCount,
                pullOrder,
                result: message,
            });
        });
        worker.postMessage({
            ...input.startMessage,
            requestIdentifier: input.requestIdentifier,
        });
    }).finally(() => {
        worker.terminate();
        workers.delete(worker);
    });
};

export const terminateCanonicalStreamBrowserWorkers = (): void => {
    for (const worker of workers) {
        worker.terminate();
    }
    workers.clear();
};
