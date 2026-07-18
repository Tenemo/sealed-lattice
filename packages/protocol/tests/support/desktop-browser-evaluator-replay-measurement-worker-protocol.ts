import type { DesktopBrowserEvaluatorReplayMeasurement } from './desktop-browser-evaluator-replay-measurement.js';

import { requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier } from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement-case-identifier';
import {
    requireProductionDesktopBrowserMeasurementIdentity,
    requireProductionDesktopBrowserMeasurementSha512,
} from '#packages/protocol/tests/support/desktop-browser-production-measurement-identity';

const requestIdentifier = 1;

type MeasurementRequest = Readonly<{
    caseIdentifier: string;
    messageKind: 'measure-production-evaluator-replay';
    requestIdentifier: number;
}>;

type MeasurementResponse =
    | Readonly<{
          caseIdentifier: string;
          measurementJson: string;
          messageKind: 'production-evaluator-replay-measured';
          requestIdentifier: number;
      }>
    | Readonly<{
          caseIdentifier: string;
          failureMessage: string;
          messageKind: 'production-evaluator-replay-measurement-failed';
          requestIdentifier: number;
      }>;

type MeasurementWorkerEventMap = Readonly<{
    error: ErrorEvent;
    message: MessageEvent<unknown>;
    messageerror: MessageEvent<unknown>;
}>;

export type DesktopBrowserEvaluatorReplayMeasurementWorker = Readonly<{
    addEventListener<EventType extends keyof MeasurementWorkerEventMap>(
        type: EventType,
        listener: (event: MeasurementWorkerEventMap[EventType]) => void,
        options?: AddEventListenerOptions | boolean,
    ): void;
    postMessage(message: unknown): void;
    removeEventListener<EventType extends keyof MeasurementWorkerEventMap>(
        type: EventType,
        listener: (event: MeasurementWorkerEventMap[EventType]) => void,
    ): void;
    terminate(): void;
}>;

export type DesktopBrowserEvaluatorReplayMeasurementWorkerScope = Readonly<{
    addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
    postMessage(message: unknown): void;
}>;

type ActiveMeasurementWorker = Readonly<{
    fail(failure: Error): void;
}>;

const activeMeasurementWorkers = new Set<ActiveMeasurementWorker>();

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const requirePlainRecord = (
    value: unknown,
    fieldName: string,
): Record<string, unknown> => {
    if (!isPlainRecord(value)) {
        throw new Error(
            `Desktop-browser evaluator-replay measurement ${fieldName} must be an object.`,
        );
    }
    return value;
};

const requireExactCount = (value: unknown, fieldName: string): number => {
    if (!Number.isSafeInteger(value) || Number(value) < 0) {
        throw new Error(
            `Desktop-browser evaluator-replay measurement ${fieldName} must be a nonnegative exact integer.`,
        );
    }
    return Number(value);
};

const requireElapsedMilliseconds = (value: unknown): number => {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        throw new Error(
            'Desktop-browser evaluator-replay measurement elapsedMilliseconds must be a nonnegative finite number.',
        );
    }
    return value;
};

const copyBoundaryBufferTraffic = (
    value: unknown,
): DesktopBrowserEvaluatorReplayMeasurement['boundaryBufferTraffic'] => {
    const record = requirePlainRecord(value, 'boundaryBufferTraffic');
    return Object.freeze({
        bufferCount: requireExactCount(
            record.bufferCount,
            'boundaryBufferTraffic.bufferCount',
        ),
        maximumBufferByteLength: requireExactCount(
            record.maximumBufferByteLength,
            'boundaryBufferTraffic.maximumBufferByteLength',
        ),
        totalByteLength: requireExactCount(
            record.totalByteLength,
            'boundaryBufferTraffic.totalByteLength',
        ),
    });
};

const copyCanonicalReplayCarrierTraffic = (
    value: unknown,
): DesktopBrowserEvaluatorReplayMeasurement['canonicalReplayCarrierTraffic'] => {
    const record = requirePlainRecord(value, 'canonicalReplayCarrierTraffic');
    return Object.freeze({
        boardIngressByteLength: requireExactCount(
            record.boardIngressByteLength,
            'canonicalReplayCarrierTraffic.boardIngressByteLength',
        ),
        copyByteLength: requireExactCount(
            record.copyByteLength,
            'canonicalReplayCarrierTraffic.copyByteLength',
        ),
    });
};

const copyEvaluatorKeyStoreTraffic = (
    value: unknown,
): DesktopBrowserEvaluatorReplayMeasurement['evaluatorKeyStoreTraffic'] => {
    const record = requirePlainRecord(value, 'evaluatorKeyStoreTraffic');
    return Object.freeze({
        declaredByteLength: requireExactCount(
            record.declaredByteLength,
            'evaluatorKeyStoreTraffic.declaredByteLength',
        ),
        distinctReadByteLength: requireExactCount(
            record.distinctReadByteLength,
            'evaluatorKeyStoreTraffic.distinctReadByteLength',
        ),
        readCount: requireExactCount(
            record.readCount,
            'evaluatorKeyStoreTraffic.readCount',
        ),
        rereadByteLength: requireExactCount(
            record.rereadByteLength,
            'evaluatorKeyStoreTraffic.rereadByteLength',
        ),
        requestedReadByteLength: requireExactCount(
            record.requestedReadByteLength,
            'evaluatorKeyStoreTraffic.requestedReadByteLength',
        ),
        returnedReadByteLength: requireExactCount(
            record.returnedReadByteLength,
            'evaluatorKeyStoreTraffic.returnedReadByteLength',
        ),
    });
};

const copyPublicOutputHashes = (
    value: unknown,
): DesktopBrowserEvaluatorReplayMeasurement['publicOutputHashes'] => {
    const record = requirePlainRecord(value, 'publicOutputHashes');
    return Object.freeze({
        canonicalReplayCarrierSha512:
            requireProductionDesktopBrowserMeasurementSha512(
                record.canonicalReplayCarrierSha512,
                'publicOutputHashes.canonicalReplayCarrierSha512',
            ),
    });
};

const copyWasmMemory = (
    value: unknown,
): DesktopBrowserEvaluatorReplayMeasurement['wasmMemory'] => {
    const record = requirePlainRecord(value, 'wasmMemory');
    return Object.freeze({
        finalByteLength: requireExactCount(
            record.finalByteLength,
            'wasmMemory.finalByteLength',
        ),
        growthByteLength: requireExactCount(
            record.growthByteLength,
            'wasmMemory.growthByteLength',
        ),
        growthObservationCount: requireExactCount(
            record.growthObservationCount,
            'wasmMemory.growthObservationCount',
        ),
        initialByteLength: requireExactCount(
            record.initialByteLength,
            'wasmMemory.initialByteLength',
        ),
        observationCount: requireExactCount(
            record.observationCount,
            'wasmMemory.observationCount',
        ),
        peakByteLength: requireExactCount(
            record.peakByteLength,
            'wasmMemory.peakByteLength',
        ),
    });
};

const enforceMeasurementAccounting = (
    measurement: DesktopBrowserEvaluatorReplayMeasurement,
): void => {
    const storeTraffic = measurement.evaluatorKeyStoreTraffic;
    const carrierTraffic = measurement.canonicalReplayCarrierTraffic;
    const boundaryTraffic = measurement.boundaryBufferTraffic;
    const wasmMemory = measurement.wasmMemory;
    if (
        storeTraffic.declaredByteLength === 0 ||
        storeTraffic.readCount === 0 ||
        storeTraffic.declaredByteLength !==
            storeTraffic.distinctReadByteLength ||
        storeTraffic.requestedReadByteLength !==
            storeTraffic.returnedReadByteLength ||
        storeTraffic.rereadByteLength !==
            storeTraffic.requestedReadByteLength -
                storeTraffic.distinctReadByteLength
    ) {
        throw new Error(
            'Desktop-browser evaluator-replay measurement store accounting is inconsistent.',
        );
    }
    if (
        carrierTraffic.copyByteLength === 0 ||
        carrierTraffic.copyByteLength !== carrierTraffic.boardIngressByteLength
    ) {
        throw new Error(
            'Desktop-browser evaluator-replay measurement carrier accounting is inconsistent.',
        );
    }
    if (
        boundaryTraffic.bufferCount !== storeTraffic.readCount + 2 ||
        boundaryTraffic.totalByteLength !==
            storeTraffic.returnedReadByteLength +
                carrierTraffic.copyByteLength +
                carrierTraffic.boardIngressByteLength ||
        boundaryTraffic.maximumBufferByteLength === 0 ||
        boundaryTraffic.maximumBufferByteLength >
            boundaryTraffic.totalByteLength ||
        boundaryTraffic.maximumBufferByteLength < carrierTraffic.copyByteLength
    ) {
        throw new Error(
            'Desktop-browser evaluator-replay measurement boundary-buffer accounting is inconsistent.',
        );
    }
    if (measurement.schedulerYieldCount !== storeTraffic.readCount) {
        throw new Error(
            'Desktop-browser evaluator-replay measurement scheduler accounting is inconsistent.',
        );
    }
    if (
        wasmMemory.finalByteLength !==
            wasmMemory.initialByteLength + wasmMemory.growthByteLength ||
        wasmMemory.peakByteLength < wasmMemory.initialByteLength ||
        wasmMemory.peakByteLength < wasmMemory.finalByteLength ||
        wasmMemory.observationCount === 0 ||
        wasmMemory.growthObservationCount > wasmMemory.observationCount ||
        (wasmMemory.growthByteLength === 0) !==
            (wasmMemory.growthObservationCount === 0)
    ) {
        throw new Error(
            'Desktop-browser evaluator-replay measurement WASM-memory accounting is inconsistent.',
        );
    }
};

export const validateDesktopBrowserEvaluatorReplayMeasurement = (
    value: unknown,
    selectedCaseIdentifier: string,
): DesktopBrowserEvaluatorReplayMeasurement => {
    const requiredCaseIdentifier =
        requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier(
            selectedCaseIdentifier,
        );
    const record = requirePlainRecord(value, 'result');
    if (record.caseIdentifier !== requiredCaseIdentifier) {
        throw new Error(
            'The desktop-browser evaluator-replay measurement returned a mismatched case identifier.',
        );
    }
    const measurement = Object.freeze({
        boundaryBufferTraffic: copyBoundaryBufferTraffic(
            record.boundaryBufferTraffic,
        ),
        canonicalReplayCarrierTraffic: copyCanonicalReplayCarrierTraffic(
            record.canonicalReplayCarrierTraffic,
        ),
        caseIdentifier: requiredCaseIdentifier,
        elapsedMilliseconds: requireElapsedMilliseconds(
            record.elapsedMilliseconds,
        ),
        evaluatorKeyStoreTraffic: copyEvaluatorKeyStoreTraffic(
            record.evaluatorKeyStoreTraffic,
        ),
        measurementIdentity: requireProductionDesktopBrowserMeasurementIdentity(
            record.measurementIdentity,
        ),
        publicOutputHashes: copyPublicOutputHashes(record.publicOutputHashes),
        schedulerYieldCount: requireExactCount(
            record.schedulerYieldCount,
            'schedulerYieldCount',
        ),
        wasmMemory: copyWasmMemory(record.wasmMemory),
    });
    enforceMeasurementAccounting(measurement);
    return measurement;
};

const isMeasurementRequest = (value: unknown): value is MeasurementRequest =>
    isPlainRecord(value) &&
    value.messageKind === 'measure-production-evaluator-replay' &&
    value.requestIdentifier === requestIdentifier &&
    typeof value.caseIdentifier === 'string';

const requireMeasurementResponse = (
    value: unknown,
    selectedCaseIdentifier: string,
): MeasurementResponse => {
    if (
        !isPlainRecord(value) ||
        value.requestIdentifier !== requestIdentifier ||
        value.caseIdentifier !== selectedCaseIdentifier
    ) {
        throw new Error(
            'The desktop-browser evaluator-replay measurement worker returned malformed data.',
        );
    }
    if (
        value.messageKind === 'production-evaluator-replay-measured' &&
        typeof value.measurementJson === 'string'
    ) {
        return value as MeasurementResponse;
    }
    if (
        value.messageKind ===
            'production-evaluator-replay-measurement-failed' &&
        typeof value.failureMessage === 'string' &&
        value.failureMessage.length > 0
    ) {
        return value as MeasurementResponse;
    }
    throw new Error(
        'The desktop-browser evaluator-replay measurement worker returned malformed data.',
    );
};

export const runDesktopBrowserEvaluatorReplayMeasurementWorker = (input: {
    caseIdentifier: string;
    worker: DesktopBrowserEvaluatorReplayMeasurementWorker;
}): Promise<DesktopBrowserEvaluatorReplayMeasurement> => {
    const selectedCaseIdentifier =
        requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier(
            input.caseIdentifier,
        );

    return new Promise<DesktopBrowserEvaluatorReplayMeasurement>(
        (resolve, reject) => {
            let settled = false;
            const cleanup = (): void => {
                input.worker.removeEventListener('error', handleError);
                input.worker.removeEventListener('message', handleMessage);
                input.worker.removeEventListener(
                    'messageerror',
                    handleMessageError,
                );
                input.worker.terminate();
                activeMeasurementWorkers.delete(activeWorker);
            };
            const fail = (failure: Error): void => {
                if (settled) {
                    return;
                }
                settled = true;
                cleanup();
                reject(failure);
            };
            const complete = (
                measurement: DesktopBrowserEvaluatorReplayMeasurement,
            ): void => {
                if (settled) {
                    return;
                }
                settled = true;
                cleanup();
                resolve(measurement);
            };
            const handleError = (event: ErrorEvent): void => {
                fail(
                    event.error instanceof Error
                        ? event.error
                        : new Error(
                              'The desktop-browser evaluator-replay measurement worker failed.',
                          ),
                );
            };
            const handleMessageError = (): void => {
                fail(
                    new Error(
                        'The desktop-browser evaluator-replay measurement worker response could not be cloned.',
                    ),
                );
            };
            const handleMessage = (event: MessageEvent<unknown>): void => {
                let response: MeasurementResponse;
                try {
                    response = requireMeasurementResponse(
                        event.data,
                        selectedCaseIdentifier,
                    );
                } catch (error) {
                    fail(
                        error instanceof Error
                            ? error
                            : new Error(
                                  'The desktop-browser evaluator-replay measurement worker returned malformed data.',
                              ),
                    );
                    return;
                }
                if (
                    response.messageKind ===
                    'production-evaluator-replay-measurement-failed'
                ) {
                    fail(new Error(response.failureMessage));
                    return;
                }
                let parsedMeasurement: unknown;
                try {
                    parsedMeasurement = JSON.parse(response.measurementJson);
                } catch (error) {
                    fail(
                        Object.assign(
                            new Error(
                                'The desktop-browser evaluator-replay measurement worker returned invalid JSON.',
                            ),
                            { cause: error },
                        ),
                    );
                    return;
                }
                try {
                    complete(
                        validateDesktopBrowserEvaluatorReplayMeasurement(
                            parsedMeasurement,
                            selectedCaseIdentifier,
                        ),
                    );
                } catch (error) {
                    fail(
                        error instanceof Error
                            ? error
                            : new Error(
                                  'The desktop-browser evaluator-replay measurement worker returned an invalid measurement.',
                              ),
                    );
                }
            };
            const activeWorker: ActiveMeasurementWorker = Object.freeze({
                fail,
            });

            activeMeasurementWorkers.add(activeWorker);
            input.worker.addEventListener('error', handleError, { once: true });
            input.worker.addEventListener('message', handleMessage);
            input.worker.addEventListener('messageerror', handleMessageError, {
                once: true,
            });
            try {
                input.worker.postMessage({
                    caseIdentifier: selectedCaseIdentifier,
                    messageKind: 'measure-production-evaluator-replay',
                    requestIdentifier,
                } satisfies MeasurementRequest);
            } catch (error) {
                fail(
                    error instanceof Error
                        ? error
                        : new Error(
                              'The desktop-browser evaluator-replay measurement request could not be cloned.',
                          ),
                );
            }
        },
    );
};

export const terminateDesktopBrowserEvaluatorReplayMeasurementWorkers =
    (): void => {
        for (const activeWorker of [...activeMeasurementWorkers]) {
            activeWorker.fail(
                new Error(
                    'The desktop-browser evaluator-replay measurement worker was terminated during cleanup.',
                ),
            );
        }
    };

const failureMessageFrom = (failure: unknown): string =>
    failure instanceof Error && failure.message.length > 0
        ? failure.message
        : 'The production evaluator-replay measurement failed.';

export const installDesktopBrowserEvaluatorReplayMeasurementWorkerProtocol = (
    input: Readonly<{
        measureCase(
            caseIdentifier: string,
        ): Promise<DesktopBrowserEvaluatorReplayMeasurement>;
        workerScope: DesktopBrowserEvaluatorReplayMeasurementWorkerScope;
    }>,
): void => {
    let requestAccepted = false;
    input.workerScope.addEventListener('message', (event) => {
        const request = event.data;
        if (!isMeasurementRequest(request)) {
            throw new Error(
                'The production evaluator-replay measurement worker received a malformed request.',
            );
        }
        const selectedCaseIdentifier =
            requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier(
                request.caseIdentifier,
            );
        if (requestAccepted) {
            input.workerScope.postMessage({
                caseIdentifier: selectedCaseIdentifier,
                failureMessage:
                    'The production evaluator-replay measurement worker accepts one request.',
                messageKind: 'production-evaluator-replay-measurement-failed',
                requestIdentifier,
            } satisfies MeasurementResponse);
            return;
        }
        requestAccepted = true;
        void input
            .measureCase(selectedCaseIdentifier)
            .then((measurement) => {
                const validatedMeasurement =
                    validateDesktopBrowserEvaluatorReplayMeasurement(
                        measurement,
                        selectedCaseIdentifier,
                    );
                input.workerScope.postMessage({
                    caseIdentifier: selectedCaseIdentifier,
                    measurementJson: JSON.stringify(validatedMeasurement),
                    messageKind: 'production-evaluator-replay-measured',
                    requestIdentifier,
                } satisfies MeasurementResponse);
            })
            .catch((failure: unknown) => {
                input.workerScope.postMessage({
                    caseIdentifier: selectedCaseIdentifier,
                    failureMessage: failureMessageFrom(failure),
                    messageKind:
                        'production-evaluator-replay-measurement-failed',
                    requestIdentifier,
                } satisfies MeasurementResponse);
            });
    });
};
