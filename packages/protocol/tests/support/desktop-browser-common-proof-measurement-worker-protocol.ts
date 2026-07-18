import type { DesktopBrowserCommonProofMeasurement } from './desktop-browser-common-proof-measurement.js';

import { requireDesktopBrowserCommonProofMeasurementCaseIdentifier } from '#packages/protocol/tests/support/desktop-browser-common-proof-measurement-case-identifier';
import {
    requireProductionDesktopBrowserMeasurementIdentity,
    requireProductionDesktopBrowserMeasurementSha512,
} from '#packages/protocol/tests/support/desktop-browser-production-measurement-identity';

const requestIdentifier = 1;

type MeasurementRequest = Readonly<{
    caseIdentifier: string;
    messageKind: 'measure-production-common-proof';
    requestIdentifier: number;
}>;

type MeasurementCompletedResponse = Readonly<{
    caseIdentifier: string;
    measurementJson: string;
    messageKind: 'production-common-proof-measured';
    requestIdentifier: number;
}>;

type MeasurementFailedResponse = Readonly<{
    caseIdentifier: string;
    failureMessage: string;
    messageKind: 'production-common-proof-measurement-failed';
    requestIdentifier: number;
}>;

type MeasurementWorkerEventMap = Readonly<{
    error: ErrorEvent;
    message: MessageEvent<unknown>;
    messageerror: MessageEvent<unknown>;
}>;

export type DesktopBrowserCommonProofMeasurementWorker = Readonly<{
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

export type DesktopBrowserCommonProofMeasurementWorkerScope = Readonly<{
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
            `Desktop-browser common-proof measurement ${fieldName} must be an object.`,
        );
    }
    return value;
};

const requireExactCount = (value: unknown, fieldName: string): number => {
    if (!Number.isSafeInteger(value) || Number(value) < 0) {
        throw new Error(
            `Desktop-browser common-proof measurement ${fieldName} must be a nonnegative exact integer.`,
        );
    }
    return Number(value);
};

const requireElapsedMilliseconds = (value: unknown): number => {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        throw new Error(
            'Desktop-browser common-proof measurement elapsedMilliseconds must be a nonnegative finite number.',
        );
    }
    return value;
};

const copyBoundaryBufferTraffic = (
    value: unknown,
): DesktopBrowserCommonProofMeasurement['boundaryBufferTraffic'] => {
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

const copyCanonicalOutputTraffic = (
    value: unknown,
): DesktopBrowserCommonProofMeasurement['canonicalOutputTraffic'] => {
    const record = requirePlainRecord(value, 'canonicalOutputTraffic');
    return Object.freeze({
        authenticatedInputReadByteLength: requireExactCount(
            record.authenticatedInputReadByteLength,
            'canonicalOutputTraffic.authenticatedInputReadByteLength',
        ),
        authenticatedInputReadCount: requireExactCount(
            record.authenticatedInputReadCount,
            'canonicalOutputTraffic.authenticatedInputReadCount',
        ),
        authenticatedInputRequestedByteLength: requireExactCount(
            record.authenticatedInputRequestedByteLength,
            'canonicalOutputTraffic.authenticatedInputRequestedByteLength',
        ),
        committedByteLength: requireExactCount(
            record.committedByteLength,
            'canonicalOutputTraffic.committedByteLength',
        ),
        committedChunkCount: requireExactCount(
            record.committedChunkCount,
            'canonicalOutputTraffic.committedChunkCount',
        ),
        outputReadByteLength: requireExactCount(
            record.outputReadByteLength,
            'canonicalOutputTraffic.outputReadByteLength',
        ),
        outputReadCount: requireExactCount(
            record.outputReadCount,
            'canonicalOutputTraffic.outputReadCount',
        ),
        outputRequestedByteLength: requireExactCount(
            record.outputRequestedByteLength,
            'canonicalOutputTraffic.outputRequestedByteLength',
        ),
        sealCount: requireExactCount(
            record.sealCount,
            'canonicalOutputTraffic.sealCount',
        ),
    });
};

const copyCheckpointTraffic = (
    value: unknown,
): DesktopBrowserCommonProofMeasurement['checkpointTraffic'] => {
    const record = requirePlainRecord(value, 'checkpointTraffic');
    return Object.freeze({
        copiedResumeDescriptorByteLength: requireExactCount(
            record.copiedResumeDescriptorByteLength,
            'checkpointTraffic.copiedResumeDescriptorByteLength',
        ),
        copiedResumeDescriptorCount: requireExactCount(
            record.copiedResumeDescriptorCount,
            'checkpointTraffic.copiedResumeDescriptorCount',
        ),
        publishedCanonicalStateByteLength: requireExactCount(
            record.publishedCanonicalStateByteLength,
            'checkpointTraffic.publishedCanonicalStateByteLength',
        ),
        publishedCheckpointCount: requireExactCount(
            record.publishedCheckpointCount,
            'checkpointTraffic.publishedCheckpointCount',
        ),
        publishedCursorManifestByteLength: requireExactCount(
            record.publishedCursorManifestByteLength,
            'checkpointTraffic.publishedCursorManifestByteLength',
        ),
        publishedPrivateRandomnessIdentifierByteLength: requireExactCount(
            record.publishedPrivateRandomnessIdentifierByteLength,
            'checkpointTraffic.publishedPrivateRandomnessIdentifierByteLength',
        ),
        publishedStableBindingByteLength: requireExactCount(
            record.publishedStableBindingByteLength,
            'checkpointTraffic.publishedStableBindingByteLength',
        ),
        restoredCanonicalStateByteLength: requireExactCount(
            record.restoredCanonicalStateByteLength,
            'checkpointTraffic.restoredCanonicalStateByteLength',
        ),
        restoredCheckpointCount: requireExactCount(
            record.restoredCheckpointCount,
            'checkpointTraffic.restoredCheckpointCount',
        ),
    });
};

const copyExternalMemoryTraffic = (
    value: unknown,
): DesktopBrowserCommonProofMeasurement['externalMemoryTraffic'] => {
    const record = requirePlainRecord(value, 'externalMemoryTraffic');
    return Object.freeze({
        appendByteLength: requireExactCount(
            record.appendByteLength,
            'externalMemoryTraffic.appendByteLength',
        ),
        appendOperationCount: requireExactCount(
            record.appendOperationCount,
            'externalMemoryTraffic.appendOperationCount',
        ),
        createOperationCount: requireExactCount(
            record.createOperationCount,
            'externalMemoryTraffic.createOperationCount',
        ),
        createdDeclaredByteLength: requireExactCount(
            record.createdDeclaredByteLength,
            'externalMemoryTraffic.createdDeclaredByteLength',
        ),
        deleteOperationCount: requireExactCount(
            record.deleteOperationCount,
            'externalMemoryTraffic.deleteOperationCount',
        ),
        operationCount: requireExactCount(
            record.operationCount,
            'externalMemoryTraffic.operationCount',
        ),
        peakLiveDeclaredByteLength: requireExactCount(
            record.peakLiveDeclaredByteLength,
            'externalMemoryTraffic.peakLiveDeclaredByteLength',
        ),
        prefixReplayTransactionCount: requireExactCount(
            record.prefixReplayTransactionCount,
            'externalMemoryTraffic.prefixReplayTransactionCount',
        ),
        readOperationCount: requireExactCount(
            record.readOperationCount,
            'externalMemoryTraffic.readOperationCount',
        ),
        requestedReadByteLength: requireExactCount(
            record.requestedReadByteLength,
            'externalMemoryTraffic.requestedReadByteLength',
        ),
        returnedReadByteLength: requireExactCount(
            record.returnedReadByteLength,
            'externalMemoryTraffic.returnedReadByteLength',
        ),
        sealOperationCount: requireExactCount(
            record.sealOperationCount,
            'externalMemoryTraffic.sealOperationCount',
        ),
        transactionCount: requireExactCount(
            record.transactionCount,
            'externalMemoryTraffic.transactionCount',
        ),
    });
};

const copyHandoffTraffic = (
    value: unknown,
): DesktopBrowserCommonProofMeasurement['handoffTraffic'] => {
    const record = requirePlainRecord(value, 'handoffTraffic');
    return Object.freeze({
        armedHandoffCount: requireExactCount(
            record.armedHandoffCount,
            'handoffTraffic.armedHandoffCount',
        ),
        returnedMarkerByteLength: requireExactCount(
            record.returnedMarkerByteLength,
            'handoffTraffic.returnedMarkerByteLength',
        ),
    });
};

const copyPublicOutputHashes = (
    value: unknown,
): DesktopBrowserCommonProofMeasurement['publicOutputHashes'] => {
    const record = requirePlainRecord(value, 'publicOutputHashes');
    return Object.freeze({
        canonicalProofStreamSha512:
            requireProductionDesktopBrowserMeasurementSha512(
                record.canonicalProofStreamSha512,
                'publicOutputHashes.canonicalProofStreamSha512',
            ),
    });
};

const copyWasmMemory = (
    value: unknown,
): DesktopBrowserCommonProofMeasurement['wasmMemory'] => {
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

export const validateDesktopBrowserCommonProofMeasurement = (
    value: unknown,
    selectedCaseIdentifier: string,
): DesktopBrowserCommonProofMeasurement => {
    const requiredCaseIdentifier =
        requireDesktopBrowserCommonProofMeasurementCaseIdentifier(
            selectedCaseIdentifier,
        );
    const record = requirePlainRecord(value, 'result');
    if (record.caseIdentifier !== requiredCaseIdentifier) {
        throw new Error(
            'The desktop-browser common-proof measurement returned a mismatched case identifier.',
        );
    }
    if (
        record.executionKind !== 'fresh' &&
        record.executionKind !== 'resumed'
    ) {
        throw new Error(
            'Desktop-browser common-proof measurement executionKind must be fresh or resumed.',
        );
    }
    return Object.freeze({
        boundaryBufferTraffic: copyBoundaryBufferTraffic(
            record.boundaryBufferTraffic,
        ),
        canonicalOutputTraffic: copyCanonicalOutputTraffic(
            record.canonicalOutputTraffic,
        ),
        caseIdentifier: requiredCaseIdentifier,
        checkpointTraffic: copyCheckpointTraffic(record.checkpointTraffic),
        elapsedMilliseconds: requireElapsedMilliseconds(
            record.elapsedMilliseconds,
        ),
        executionKind: record.executionKind,
        externalMemoryTraffic: copyExternalMemoryTraffic(
            record.externalMemoryTraffic,
        ),
        handoffTraffic: copyHandoffTraffic(record.handoffTraffic),
        measurementIdentity: requireProductionDesktopBrowserMeasurementIdentity(
            record.measurementIdentity,
        ),
        publicOutputHashes: copyPublicOutputHashes(record.publicOutputHashes),
        wasmMemory: copyWasmMemory(record.wasmMemory),
    });
};

const isMeasurementRequest = (value: unknown): value is MeasurementRequest =>
    isPlainRecord(value) &&
    value.messageKind === 'measure-production-common-proof' &&
    value.requestIdentifier === requestIdentifier &&
    typeof value.caseIdentifier === 'string';

const requireMeasurementResponse = (
    value: unknown,
    selectedCaseIdentifier: string,
): MeasurementCompletedResponse | MeasurementFailedResponse => {
    if (
        !isPlainRecord(value) ||
        value.requestIdentifier !== requestIdentifier ||
        value.caseIdentifier !== selectedCaseIdentifier
    ) {
        throw new Error(
            'The desktop-browser common-proof measurement worker returned malformed data.',
        );
    }
    if (
        value.messageKind === 'production-common-proof-measured' &&
        typeof value.measurementJson === 'string'
    ) {
        return value as MeasurementCompletedResponse;
    }
    if (
        value.messageKind === 'production-common-proof-measurement-failed' &&
        typeof value.failureMessage === 'string' &&
        value.failureMessage.length > 0
    ) {
        return value as MeasurementFailedResponse;
    }
    throw new Error(
        'The desktop-browser common-proof measurement worker returned malformed data.',
    );
};

export const runDesktopBrowserCommonProofMeasurementWorker = (input: {
    caseIdentifier: string;
    worker: DesktopBrowserCommonProofMeasurementWorker;
}): Promise<DesktopBrowserCommonProofMeasurement> => {
    const selectedCaseIdentifier =
        requireDesktopBrowserCommonProofMeasurementCaseIdentifier(
            input.caseIdentifier,
        );

    return new Promise<DesktopBrowserCommonProofMeasurement>(
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
                measurement: DesktopBrowserCommonProofMeasurement,
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
                              'The desktop-browser common-proof measurement worker failed.',
                          ),
                );
            };
            const handleMessageError = (): void => {
                fail(
                    new Error(
                        'The desktop-browser common-proof measurement worker response could not be cloned.',
                    ),
                );
            };
            const handleMessage = (event: MessageEvent<unknown>): void => {
                let response:
                    | MeasurementCompletedResponse
                    | MeasurementFailedResponse;
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
                                  'The desktop-browser common-proof measurement worker returned malformed data.',
                              ),
                    );
                    return;
                }
                if (
                    response.messageKind ===
                    'production-common-proof-measurement-failed'
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
                                'The desktop-browser common-proof measurement worker returned invalid JSON.',
                            ),
                            { cause: error },
                        ),
                    );
                    return;
                }
                try {
                    complete(
                        validateDesktopBrowserCommonProofMeasurement(
                            parsedMeasurement,
                            selectedCaseIdentifier,
                        ),
                    );
                } catch (error) {
                    fail(
                        error instanceof Error
                            ? error
                            : new Error(
                                  'The desktop-browser common-proof measurement worker returned an invalid measurement.',
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
                    messageKind: 'measure-production-common-proof',
                    requestIdentifier,
                } satisfies MeasurementRequest);
            } catch (error) {
                fail(
                    error instanceof Error
                        ? error
                        : new Error(
                              'The desktop-browser common-proof measurement request could not be cloned.',
                          ),
                );
            }
        },
    );
};

export const terminateDesktopBrowserCommonProofMeasurementWorkers =
    (): void => {
        for (const activeWorker of [...activeMeasurementWorkers]) {
            activeWorker.fail(
                new Error(
                    'The desktop-browser common-proof measurement worker was terminated during cleanup.',
                ),
            );
        }
    };

const failureMessageFrom = (failure: unknown): string =>
    failure instanceof Error && failure.message.length > 0
        ? failure.message
        : 'The production common-proof measurement failed.';

export const installDesktopBrowserCommonProofMeasurementWorkerProtocol = (
    input: Readonly<{
        measureCase(
            caseIdentifier: string,
        ): Promise<DesktopBrowserCommonProofMeasurement>;
        workerScope: DesktopBrowserCommonProofMeasurementWorkerScope;
    }>,
): void => {
    let requestAccepted = false;
    input.workerScope.addEventListener('message', (event) => {
        const request = event.data;
        if (!isMeasurementRequest(request)) {
            throw new Error(
                'The production common-proof measurement worker received a malformed request.',
            );
        }
        const selectedCaseIdentifier =
            requireDesktopBrowserCommonProofMeasurementCaseIdentifier(
                request.caseIdentifier,
            );
        if (requestAccepted) {
            input.workerScope.postMessage({
                caseIdentifier: selectedCaseIdentifier,
                failureMessage:
                    'The production common-proof measurement worker accepts one request.',
                messageKind: 'production-common-proof-measurement-failed',
                requestIdentifier,
            } satisfies MeasurementFailedResponse);
            return;
        }
        requestAccepted = true;
        void input
            .measureCase(selectedCaseIdentifier)
            .then((measurement) => {
                const validatedMeasurement =
                    validateDesktopBrowserCommonProofMeasurement(
                        measurement,
                        selectedCaseIdentifier,
                    );
                input.workerScope.postMessage({
                    caseIdentifier: selectedCaseIdentifier,
                    measurementJson: JSON.stringify(validatedMeasurement),
                    messageKind: 'production-common-proof-measured',
                    requestIdentifier,
                } satisfies MeasurementCompletedResponse);
            })
            .catch((failure: unknown) => {
                input.workerScope.postMessage({
                    caseIdentifier: selectedCaseIdentifier,
                    failureMessage: failureMessageFrom(failure),
                    messageKind: 'production-common-proof-measurement-failed',
                    requestIdentifier,
                } satisfies MeasurementFailedResponse);
            });
    });
};
