import { afterEach, describe, expect, it } from 'vitest';

import type { DesktopBrowserCommonProofMeasurement } from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement';
import {
    installDesktopBrowserCommonProofMeasurementWorkerProtocol,
    runDesktopBrowserCommonProofMeasurementWorker,
    terminateDesktopBrowserCommonProofMeasurementWorkers,
    validateDesktopBrowserCommonProofMeasurement,
    type DesktopBrowserCommonProofMeasurementWorker,
} from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement-worker-protocol';

const caseIdentifier = 'direct-ballot-fresh';

const measurementIdentity = Object.freeze({
    actionContextHash: '11'.repeat(64),
    inputCorpusHash: '22'.repeat(64),
    manifestHash: '33'.repeat(64),
    packagedWasmSha256: '44'.repeat(32),
    runtimeBuildManifestHash: '55'.repeat(64),
    suiteIdentifier: '66'.repeat(64),
});

const measurement = Object.freeze({
    boundaryBufferTraffic: Object.freeze({
        bufferCount: 12,
        maximumBufferByteLength: 4096,
        totalByteLength: 24_576,
    }),
    canonicalOutputTraffic: Object.freeze({
        authenticatedInputReadByteLength: 1024,
        authenticatedInputReadCount: 2,
        authenticatedInputRequestedByteLength: 1024,
        committedByteLength: 8192,
        committedChunkCount: 4,
        outputReadByteLength: 8192,
        outputReadCount: 4,
        outputRequestedByteLength: 8192,
        sealCount: 1,
    }),
    caseIdentifier,
    checkpointTraffic: Object.freeze({
        copiedResumeDescriptorByteLength: 256,
        copiedResumeDescriptorCount: 1,
        publishedCanonicalStateByteLength: 4096,
        publishedCheckpointCount: 2,
        publishedCursorManifestByteLength: 512,
        publishedPrivateRandomnessIdentifierByteLength: 64,
        publishedStableBindingByteLength: 64,
        restoredCanonicalStateByteLength: 2048,
        restoredCheckpointCount: 1,
    }),
    elapsedMilliseconds: 1234.5,
    executionKind: 'fresh',
    externalMemoryTraffic: Object.freeze({
        appendByteLength: 16_384,
        appendOperationCount: 4,
        createOperationCount: 2,
        createdDeclaredByteLength: 32_768,
        deleteOperationCount: 2,
        operationCount: 16,
        peakLiveDeclaredByteLength: 32_768,
        prefixReplayTransactionCount: 1,
        readOperationCount: 6,
        requestedReadByteLength: 12_288,
        returnedReadByteLength: 12_288,
        sealOperationCount: 2,
        transactionCount: 5,
    }),
    handoffTraffic: Object.freeze({
        armedHandoffCount: 1,
        returnedMarkerByteLength: 96,
    }),
    measurementIdentity,
    publicOutputHashes: Object.freeze({
        canonicalProofStreamSha512: '77'.repeat(64),
    }),
    wasmMemory: Object.freeze({
        finalByteLength: 196_608,
        growthByteLength: 131_072,
        growthObservationCount: 2,
        initialByteLength: 65_536,
        observationCount: 48,
        peakByteLength: 196_608,
    }),
} satisfies DesktopBrowserCommonProofMeasurement);

type WorkerEventType = 'error' | 'message' | 'messageerror';

class ControlledMeasurementWorker {
    readonly listeners = new Map<
        WorkerEventType,
        Set<(event: unknown) => void>
    >();
    readonly postedMessages: unknown[] = [];
    postFailure: Error | undefined;
    terminationCount = 0;

    public addEventListener(
        type: WorkerEventType,
        listener: (event: unknown) => void,
    ): void {
        const listeners = this.listeners.get(type) ?? new Set();
        listeners.add(listener);
        this.listeners.set(type, listeners);
    }

    public emitError(error: Error): void {
        this.emit('error', { error });
    }

    public emitMessage(data: unknown): void {
        this.emit('message', { data });
    }

    public emitMessageError(): void {
        this.emit('messageerror', { data: undefined });
    }

    public listenerCount(): number {
        let count = 0;
        for (const listeners of this.listeners.values()) {
            count += listeners.size;
        }
        return count;
    }

    public postMessage(message: unknown): void {
        if (this.postFailure !== undefined) {
            throw this.postFailure;
        }
        this.postedMessages.push(message);
    }

    public removeEventListener(
        type: WorkerEventType,
        listener: (event: unknown) => void,
    ): void {
        this.listeners.get(type)?.delete(listener);
    }

    public terminate(): void {
        this.terminationCount += 1;
    }

    private emit(type: WorkerEventType, event: unknown): void {
        for (const listener of [...(this.listeners.get(type) ?? [])]) {
            listener(event);
        }
    }
}

class ControlledWorkerScope {
    readonly postedMessages: unknown[] = [];
    messageListener: ((event: MessageEvent<unknown>) => void) | undefined;

    public addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void {
        if (type !== 'message') {
            throw new Error(
                'The controlled worker scope received a bad event type.',
            );
        }
        this.messageListener = listener;
    }

    public emitMessage(data: unknown): void {
        if (this.messageListener === undefined) {
            throw new Error('The controlled worker scope has no listener.');
        }
        this.messageListener({ data } as MessageEvent<unknown>);
    }

    public postMessage(message: unknown): void {
        this.postedMessages.push(message);
    }
}

const asMeasurementWorker = (
    worker: ControlledMeasurementWorker,
): DesktopBrowserCommonProofMeasurementWorker =>
    worker as unknown as DesktopBrowserCommonProofMeasurementWorker;

afterEach(() => {
    terminateDesktopBrowserCommonProofMeasurementWorkers();
});

describe('Desktop-browser common-proof measurement worker protocol', () => {
    it('returns only a validated frozen measurement and releases every worker listener', async () => {
        const worker = new ControlledMeasurementWorker();
        const measurementPromise =
            runDesktopBrowserCommonProofMeasurementWorker({
                caseIdentifier,
                worker: asMeasurementWorker(worker),
            });

        expect(worker.postedMessages).toEqual([
            {
                caseIdentifier,
                messageKind: 'measure-production-common-proof',
                requestIdentifier: 1,
            },
        ]);
        worker.emitMessage({
            caseIdentifier,
            measurementJson: JSON.stringify({
                ...measurement,
                ignoredWorkerField: 'not copied',
            }),
            messageKind: 'production-common-proof-measured',
            requestIdentifier: 1,
        });

        const result = await measurementPromise;
        expect(result).toEqual(measurement);
        expect(result).not.toHaveProperty('ignoredWorkerField');
        expect(Object.isFrozen(result)).toBe(true);
        expect(Object.isFrozen(result.externalMemoryTraffic)).toBe(true);
        expect(Object.isFrozen(result.measurementIdentity)).toBe(true);
        expect(Object.isFrozen(result.publicOutputHashes)).toBe(true);
        expect(worker.listenerCount()).toBe(0);
        expect(worker.terminationCount).toBe(1);
    });

    it('refuses mismatched or invalid worker results and cleans up immediately', async () => {
        const mismatchedWorker = new ControlledMeasurementWorker();
        const mismatchedPromise = runDesktopBrowserCommonProofMeasurementWorker(
            {
                caseIdentifier,
                worker: asMeasurementWorker(mismatchedWorker),
            },
        );
        mismatchedWorker.emitMessage({
            caseIdentifier: 'different-case',
            measurementJson: JSON.stringify(measurement),
            messageKind: 'production-common-proof-measured',
            requestIdentifier: 1,
        });
        await expect(mismatchedPromise).rejects.toThrow('malformed data');
        expect(mismatchedWorker.listenerCount()).toBe(0);
        expect(mismatchedWorker.terminationCount).toBe(1);

        const invalidWorker = new ControlledMeasurementWorker();
        const invalidPromise = runDesktopBrowserCommonProofMeasurementWorker({
            caseIdentifier,
            worker: asMeasurementWorker(invalidWorker),
        });
        invalidWorker.emitMessage({
            caseIdentifier,
            measurementJson: JSON.stringify({
                ...measurement,
                externalMemoryTraffic: {
                    ...measurement.externalMemoryTraffic,
                    returnedReadByteLength: -1,
                },
            }),
            messageKind: 'production-common-proof-measured',
            requestIdentifier: 1,
        });
        await expect(invalidPromise).rejects.toThrow(
            'returnedReadByteLength must be a nonnegative exact integer',
        );
        expect(invalidWorker.listenerCount()).toBe(0);
        expect(invalidWorker.terminationCount).toBe(1);

        const invalidIdentityWorker = new ControlledMeasurementWorker();
        const invalidIdentityPromise =
            runDesktopBrowserCommonProofMeasurementWorker({
                caseIdentifier,
                worker: asMeasurementWorker(invalidIdentityWorker),
            });
        invalidIdentityWorker.emitMessage({
            caseIdentifier,
            measurementJson: JSON.stringify({
                ...measurement,
                measurementIdentity: {
                    ...measurement.measurementIdentity,
                    packagedWasmSha256: 'not-a-digest',
                },
            }),
            messageKind: 'production-common-proof-measured',
            requestIdentifier: 1,
        });
        await expect(invalidIdentityPromise).rejects.toThrow(
            'identity.packagedWasmSha256 must be one lowercase SHA-256 hexadecimal digest',
        );
        expect(invalidIdentityWorker.listenerCount()).toBe(0);
        expect(invalidIdentityWorker.terminationCount).toBe(1);

        const invalidOutputHashWorker = new ControlledMeasurementWorker();
        const invalidOutputHashPromise =
            runDesktopBrowserCommonProofMeasurementWorker({
                caseIdentifier,
                worker: asMeasurementWorker(invalidOutputHashWorker),
            });
        invalidOutputHashWorker.emitMessage({
            caseIdentifier,
            measurementJson: JSON.stringify({
                ...measurement,
                publicOutputHashes: {
                    canonicalProofStreamSha512: 'A'.repeat(128),
                },
            }),
            messageKind: 'production-common-proof-measured',
            requestIdentifier: 1,
        });
        await expect(invalidOutputHashPromise).rejects.toThrow(
            'publicOutputHashes.canonicalProofStreamSha512 must be one lowercase SHA-512 hexadecimal digest',
        );
        expect(invalidOutputHashWorker.listenerCount()).toBe(0);
        expect(invalidOutputHashWorker.terminationCount).toBe(1);
    });

    it('cleans up worker errors, clone failures, request failures, and pending workers', async () => {
        const failedWorkers = [
            new ControlledMeasurementWorker(),
            new ControlledMeasurementWorker(),
            new ControlledMeasurementWorker(),
        ];
        failedWorkers[2].postFailure = new Error('request clone failed');
        const errorPromise = runDesktopBrowserCommonProofMeasurementWorker({
            caseIdentifier,
            worker: asMeasurementWorker(failedWorkers[0]),
        });
        const messageErrorPromise =
            runDesktopBrowserCommonProofMeasurementWorker({
                caseIdentifier,
                worker: asMeasurementWorker(failedWorkers[1]),
            });
        const postFailurePromise =
            runDesktopBrowserCommonProofMeasurementWorker({
                caseIdentifier,
                worker: asMeasurementWorker(failedWorkers[2]),
            });
        failedWorkers[0].emitError(new Error('worker execution failed'));
        failedWorkers[1].emitMessageError();

        await expect(errorPromise).rejects.toThrow('worker execution failed');
        await expect(messageErrorPromise).rejects.toThrow(
            'response could not be cloned',
        );
        await expect(postFailurePromise).rejects.toThrow(
            'request clone failed',
        );
        for (const worker of failedWorkers) {
            expect(worker.listenerCount()).toBe(0);
            expect(worker.terminationCount).toBe(1);
        }

        const pendingWorker = new ControlledMeasurementWorker();
        const pendingPromise = runDesktopBrowserCommonProofMeasurementWorker({
            caseIdentifier,
            worker: asMeasurementWorker(pendingWorker),
        });
        terminateDesktopBrowserCommonProofMeasurementWorkers();
        await expect(pendingPromise).rejects.toThrow(
            'terminated during cleanup',
        );
        expect(pendingWorker.listenerCount()).toBe(0);
        expect(pendingWorker.terminationCount).toBe(1);
    });

    it('validates the worker request and permits only one measurement', async () => {
        const workerScope = new ControlledWorkerScope();
        let measuredCaseIdentifier: string | undefined;
        installDesktopBrowserCommonProofMeasurementWorkerProtocol({
            measureCase: (selectedCaseIdentifier) => {
                measuredCaseIdentifier = selectedCaseIdentifier;
                return Promise.resolve(measurement);
            },
            workerScope: workerScope,
        });

        expect(() =>
            workerScope.emitMessage({ messageKind: 'unknown' }),
        ).toThrow('malformed request');
        workerScope.emitMessage({
            caseIdentifier,
            messageKind: 'measure-production-common-proof',
            requestIdentifier: 1,
        });
        await Promise.resolve();
        await Promise.resolve();

        expect(measuredCaseIdentifier).toBe(caseIdentifier);
        expect(workerScope.postedMessages).toHaveLength(1);
        const response = workerScope.postedMessages[0] as Record<
            string,
            unknown
        >;
        expect(response).toMatchObject({
            caseIdentifier,
            messageKind: 'production-common-proof-measured',
            requestIdentifier: 1,
        });
        expect(
            validateDesktopBrowserCommonProofMeasurement(
                JSON.parse(String(response.measurementJson)),
                caseIdentifier,
            ),
        ).toEqual(measurement);

        workerScope.emitMessage({
            caseIdentifier,
            messageKind: 'measure-production-common-proof',
            requestIdentifier: 1,
        });
        const repeatedRequestResponse = workerScope.postedMessages[1] as
            | Record<string, unknown>
            | undefined;
        expect(repeatedRequestResponse).toMatchObject({
            caseIdentifier,
            messageKind: 'production-common-proof-measurement-failed',
            requestIdentifier: 1,
        });
        expect(String(repeatedRequestResponse?.failureMessage)).toContain(
            'accepts one request',
        );
    });
});
