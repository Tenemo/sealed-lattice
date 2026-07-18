import {
    prepareEvaluatorReplayInClosedWorker,
    releaseVerifiedEvaluatorReplay,
    type EvaluatorKeyStoreRangeReadObservation,
    type EvaluatorKeyStoreRangeSource,
    type PreparedEvaluatorReplay,
    type TranscriptCoreKernel,
    type VerifiedAcceptedSetupAuthority,
    type VerifiedEvaluatorAggregateAuthority,
    type VerifiedEvaluatorReplay,
    type VerifiedTranscriptObject,
} from '@sealed-lattice/wasm';

import { requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier } from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement-case-identifier';
import {
    requireProductionDesktopBrowserMeasurementIdentity,
    requireProductionDesktopBrowserMeasurementSha512,
    type ProductionDesktopBrowserMeasurementIdentity,
} from '#packages/protocol/tests/support/desktop-browser-production-measurement-identity';

type StoreRange = Readonly<{
    endOffsetExclusive: bigint;
    startOffset: bigint;
}>;

export type DesktopBrowserEvaluatorReplayMeasurementWorkerSession = Readonly<{
    acceptedSetupAuthority: VerifiedAcceptedSetupAuthority;
    /** Releases all case-owned authorities and stores, including after refusal. */
    close(): Promise<void>;
    evaluatorKeyStore: EvaluatorKeyStoreRangeSource;
    evaluatorKeyStoreByteLength: bigint;
    /**
     * Positively ingests the exact canonical carrier into the live board
     * verifier in this worker and returns its retained object authority.
     */
    ingestCanonicalReplayCarrier(
        canonicalCarrierBytes: Uint8Array<ArrayBuffer>,
    ): Promise<VerifiedTranscriptObject>;
    kernel: TranscriptCoreKernel;
    measurementIdentity: ProductionDesktopBrowserMeasurementIdentity;
    verifiedAggregateAuthority: VerifiedEvaluatorAggregateAuthority;
    wasmMemory: WebAssembly.Memory;
}>;

export type ProductionDesktopBrowserEvaluatorReplayMeasurementCase = Readonly<{
    caseIdentifier: string;
    /** Opens verified production inputs without beginning evaluator replay. */
    open(): Promise<DesktopBrowserEvaluatorReplayMeasurementWorkerSession>;
}>;

export type DesktopBrowserEvaluatorReplayMeasurement = Readonly<{
    boundaryBufferTraffic: Readonly<{
        bufferCount: number;
        maximumBufferByteLength: number;
        totalByteLength: number;
    }>;
    canonicalReplayCarrierTraffic: Readonly<{
        boardIngressByteLength: number;
        copyByteLength: number;
    }>;
    caseIdentifier: string;
    elapsedMilliseconds: number;
    evaluatorKeyStoreTraffic: Readonly<{
        declaredByteLength: number;
        distinctReadByteLength: number;
        readCount: number;
        rereadByteLength: number;
        requestedReadByteLength: number;
        returnedReadByteLength: number;
    }>;
    measurementIdentity: ProductionDesktopBrowserMeasurementIdentity;
    publicOutputHashes: Readonly<{
        canonicalReplayCarrierSha512: string;
    }>;
    schedulerYieldCount: number;
    wasmMemory: Readonly<{
        finalByteLength: number;
        growthByteLength: number;
        growthObservationCount: number;
        initialByteLength: number;
        observationCount: number;
        peakByteLength: number;
    }>;
}>;

const requireByteLength = (value: number, label: string): number => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error(`${label} is not an exact byte length.`);
    }
    return value;
};

const exactNumberFromBigInt = (value: bigint, label: string): number => {
    const numberValue = Number(value);
    if (
        value < 0n ||
        !Number.isSafeInteger(numberValue) ||
        BigInt(numberValue) !== value
    ) {
        throw new Error(`${label} exceeds the exact integer range.`);
    }
    return numberValue;
};

const checkedAdd = (
    currentValue: number,
    addedValue: number,
    label: string,
): number => {
    const sum = currentValue + addedValue;
    if (
        !Number.isSafeInteger(currentValue) ||
        !Number.isSafeInteger(addedValue) ||
        addedValue < 0 ||
        !Number.isSafeInteger(sum)
    ) {
        throw new Error(`${label} exceeds the exact integer range.`);
    }
    return sum;
};

const requireOwnedBytes = (
    value: unknown,
    label: string,
): Uint8Array<ArrayBuffer> => {
    if (
        !(value instanceof Uint8Array) ||
        !(value.buffer instanceof ArrayBuffer) ||
        value.byteOffset !== 0 ||
        value.byteLength !== value.buffer.byteLength
    ) {
        throw new Error(`${label} must be one fresh owned byte buffer.`);
    }
    return value as Uint8Array<ArrayBuffer>;
};

class DesktopBrowserEvaluatorReplayMeasurementCleanupError extends Error {
    public readonly cleanupFailures: readonly unknown[];
    public readonly operationFailure: unknown;

    public constructor(
        operationFailure: unknown,
        cleanupFailures: readonly unknown[],
    ) {
        super(
            operationFailure === undefined
                ? 'The production evaluator-replay measurement cleanup failed.'
                : 'The production evaluator-replay measurement and its cleanup failed.',
        );
        this.name = 'DesktopBrowserEvaluatorReplayMeasurementCleanupError';
        this.operationFailure = operationFailure;
        this.cleanupFailures = Object.freeze([...cleanupFailures]);
    }
}

class DesktopBrowserEvaluatorReplayRecorder {
    readonly #declaredStoreByteLength: bigint;
    readonly #storeRanges: StoreRange[] = [];
    readonly #wasmMemory: WebAssembly.Memory;
    #boardIngressByteLength = 0;
    #boundaryBufferCount = 0;
    #boundaryBufferTotalByteLength = 0;
    #canonicalCarrierObserved = false;
    #copiedCarrierByteLength = 0;
    #growthObservationCount = 0;
    #initialWasmMemoryByteLength: number;
    #lastObservedWasmMemoryByteLength: number;
    #maximumBoundaryBufferByteLength = 0;
    #peakWasmMemoryByteLength: number;
    #canonicalReplayCarrierSha512: string | undefined;
    #requestedStoreReadByteLength = 0;
    #returnedStoreReadByteLength = 0;
    #schedulerYieldCount = 0;
    #storeReadCount = 0;
    #wasmMemoryObservationCount = 0;

    public constructor(
        wasmMemory: WebAssembly.Memory,
        declaredStoreByteLength: bigint,
    ) {
        if (!(wasmMemory instanceof WebAssembly.Memory)) {
            throw new Error(
                'The production evaluator-replay measurement session did not provide WASM memory.',
            );
        }
        exactNumberFromBigInt(
            declaredStoreByteLength,
            'Declared evaluator-key store byte length',
        );
        if (declaredStoreByteLength === 0n) {
            throw new Error(
                'The production evaluator-replay measurement session declared an empty evaluator-key store.',
            );
        }
        this.#wasmMemory = wasmMemory;
        this.#declaredStoreByteLength = declaredStoreByteLength;
        const initialByteLength = requireByteLength(
            wasmMemory.buffer.byteLength,
            'Initial WASM memory length',
        );
        this.#initialWasmMemoryByteLength = initialByteLength;
        this.#lastObservedWasmMemoryByteLength = initialByteLength;
        this.#peakWasmMemoryByteLength = initialByteLength;
        this.observeWasmMemory();
    }

    public observeEvaluatorKeyStoreRangeRead(
        observation: EvaluatorKeyStoreRangeReadObservation,
    ): void {
        const requestedByteLength = requireByteLength(
            observation.requestedByteLength,
            'Requested evaluator-key store range length',
        );
        const returnedByteLength = requireByteLength(
            observation.returnedByteLength,
            'Returned evaluator-key store range length',
        );
        if (
            requestedByteLength === 0 ||
            observation.storeByteOffset < 0n ||
            returnedByteLength !== requestedByteLength
        ) {
            throw new Error(
                'Evaluator-key store range observations must describe one exact nonempty range.',
            );
        }
        const endOffsetExclusive =
            observation.storeByteOffset + BigInt(requestedByteLength);
        if (endOffsetExclusive > this.#declaredStoreByteLength) {
            throw new Error(
                'The evaluator requested bytes beyond the declared evaluator-key store.',
            );
        }
        this.observeWasmMemory();
        this.#storeReadCount = checkedAdd(
            this.#storeReadCount,
            1,
            'Evaluator-key store read count',
        );
        this.#requestedStoreReadByteLength = checkedAdd(
            this.#requestedStoreReadByteLength,
            requestedByteLength,
            'Requested evaluator-key store byte length',
        );
        this.#returnedStoreReadByteLength = checkedAdd(
            this.#returnedStoreReadByteLength,
            returnedByteLength,
            'Returned evaluator-key store byte length',
        );
        this.#storeRanges.push({
            endOffsetExclusive,
            startOffset: observation.storeByteOffset,
        });
        this.observeBoundaryBufferByteLength(returnedByteLength);
    }

    public async ingestCanonicalReplayCarrier(
        canonicalCarrierBytes: Uint8Array<ArrayBuffer>,
        ingest: (
            bytes: Uint8Array<ArrayBuffer>,
        ) => Promise<VerifiedTranscriptObject>,
    ): Promise<VerifiedTranscriptObject> {
        if (this.#canonicalCarrierObserved) {
            throw new Error(
                'The production evaluator-replay measurement emitted more than one canonical carrier.',
            );
        }
        const ownedCarrier = requireOwnedBytes(
            canonicalCarrierBytes,
            'Canonical evaluator replay carrier',
        );
        if (ownedCarrier.byteLength === 0) {
            throw new Error(
                'The production evaluator-replay measurement emitted an empty canonical carrier.',
            );
        }
        this.#canonicalCarrierObserved = true;
        this.#copiedCarrierByteLength = ownedCarrier.byteLength;
        this.#boardIngressByteLength = ownedCarrier.byteLength;
        this.observeBoundaryBufferByteLength(ownedCarrier.byteLength);
        this.observeBoundaryBufferByteLength(ownedCarrier.byteLength);
        this.observeWasmMemory();
        const verifiedObject = await ingest(ownedCarrier);
        this.observeWasmMemory();
        return verifiedObject;
    }

    public observeSynchronousOperation<Result>(
        operation: () => Result,
    ): Result {
        this.observeWasmMemory();
        const result = operation();
        this.observeWasmMemory();
        return result;
    }

    public async recordCanonicalReplayCarrierHash(
        canonicalCarrierBytes: Uint8Array<ArrayBuffer>,
    ): Promise<void> {
        if (this.#canonicalReplayCarrierSha512 !== undefined) {
            throw new Error(
                'The production evaluator-replay measurement hashed more than one canonical carrier.',
            );
        }
        const digestBytes = new Uint8Array(
            await globalThis.crypto.subtle.digest(
                'SHA-512',
                canonicalCarrierBytes,
            ),
        );
        const digestHex = Array.from(digestBytes, (digestByte) =>
            digestByte.toString(16).padStart(2, '0'),
        ).join('');
        this.#canonicalReplayCarrierSha512 =
            requireProductionDesktopBrowserMeasurementSha512(
                digestHex,
                'publicOutputHashes.canonicalReplayCarrierSha512',
            );
    }

    public async yieldControl(): Promise<void> {
        this.observeWasmMemory();
        this.#schedulerYieldCount = checkedAdd(
            this.#schedulerYieldCount,
            1,
            'Evaluator scheduler yield count',
        );
        await new Promise<void>((resolve) => {
            const channel = new MessageChannel();
            channel.port1.onmessage = () => {
                channel.port1.close();
                channel.port2.close();
                resolve();
            };
            channel.port2.postMessage(undefined);
        });
        this.observeWasmMemory();
    }

    public finish(input: {
        caseIdentifier: string;
        elapsedMilliseconds: number;
        measurementIdentity: ProductionDesktopBrowserMeasurementIdentity;
    }): DesktopBrowserEvaluatorReplayMeasurement {
        if (!this.#canonicalCarrierObserved) {
            throw new Error(
                'The production evaluator-replay measurement did not emit and ingest its canonical carrier.',
            );
        }
        if (this.#canonicalReplayCarrierSha512 === undefined) {
            throw new Error(
                'The production evaluator-replay measurement did not hash its canonical carrier.',
            );
        }
        const distinctReadByteLength = this.distinctStoreReadByteLength();
        const declaredStoreByteLength = exactNumberFromBigInt(
            this.#declaredStoreByteLength,
            'Declared evaluator-key store byte length',
        );
        if (distinctReadByteLength !== declaredStoreByteLength) {
            throw new Error(
                `The evaluator read ${distinctReadByteLength} distinct store bytes, but the selected store contains ${declaredStoreByteLength}.`,
            );
        }
        this.observeWasmMemory();
        const finalWasmMemoryByteLength = requireByteLength(
            this.#wasmMemory.buffer.byteLength,
            'Final WASM memory length',
        );
        return Object.freeze({
            boundaryBufferTraffic: Object.freeze({
                bufferCount: this.#boundaryBufferCount,
                maximumBufferByteLength: this.#maximumBoundaryBufferByteLength,
                totalByteLength: this.#boundaryBufferTotalByteLength,
            }),
            canonicalReplayCarrierTraffic: Object.freeze({
                boardIngressByteLength: this.#boardIngressByteLength,
                copyByteLength: this.#copiedCarrierByteLength,
            }),
            caseIdentifier: input.caseIdentifier,
            elapsedMilliseconds: input.elapsedMilliseconds,
            evaluatorKeyStoreTraffic: Object.freeze({
                declaredByteLength: declaredStoreByteLength,
                distinctReadByteLength,
                readCount: this.#storeReadCount,
                rereadByteLength:
                    this.#requestedStoreReadByteLength - distinctReadByteLength,
                requestedReadByteLength: this.#requestedStoreReadByteLength,
                returnedReadByteLength: this.#returnedStoreReadByteLength,
            }),
            measurementIdentity: input.measurementIdentity,
            publicOutputHashes: Object.freeze({
                canonicalReplayCarrierSha512:
                    this.#canonicalReplayCarrierSha512,
            }),
            schedulerYieldCount: this.#schedulerYieldCount,
            wasmMemory: Object.freeze({
                finalByteLength: finalWasmMemoryByteLength,
                growthByteLength:
                    finalWasmMemoryByteLength -
                    this.#initialWasmMemoryByteLength,
                growthObservationCount: this.#growthObservationCount,
                initialByteLength: this.#initialWasmMemoryByteLength,
                observationCount: this.#wasmMemoryObservationCount,
                peakByteLength: this.#peakWasmMemoryByteLength,
            }),
        });
    }

    private distinctStoreReadByteLength(): number {
        const orderedRanges = [...this.#storeRanges].sort((left, right) =>
            left.startOffset < right.startOffset
                ? -1
                : left.startOffset > right.startOffset
                  ? 1
                  : 0,
        );
        let coveredByteLength = 0n;
        let mergedEndOffset = 0n;
        for (const range of orderedRanges) {
            if (range.startOffset > mergedEndOffset) {
                throw new Error(
                    'The evaluator did not read a contiguous complete evaluator-key store.',
                );
            }
            if (range.endOffsetExclusive > mergedEndOffset) {
                coveredByteLength +=
                    range.endOffsetExclusive -
                    (range.startOffset > mergedEndOffset
                        ? range.startOffset
                        : mergedEndOffset);
                mergedEndOffset = range.endOffsetExclusive;
            }
        }
        return exactNumberFromBigInt(
            coveredByteLength,
            'Distinct evaluator-key store read byte length',
        );
    }

    private observeBoundaryBufferByteLength(value: number): void {
        const byteLength = requireByteLength(
            value,
            'Boundary buffer byte length',
        );
        this.#boundaryBufferCount = checkedAdd(
            this.#boundaryBufferCount,
            1,
            'Boundary buffer count',
        );
        this.#boundaryBufferTotalByteLength = checkedAdd(
            this.#boundaryBufferTotalByteLength,
            byteLength,
            'Boundary buffer total byte length',
        );
        this.#maximumBoundaryBufferByteLength = Math.max(
            this.#maximumBoundaryBufferByteLength,
            byteLength,
        );
    }

    private observeWasmMemory(): void {
        const observedByteLength = requireByteLength(
            this.#wasmMemory.buffer.byteLength,
            'Observed WASM memory length',
        );
        this.#wasmMemoryObservationCount = checkedAdd(
            this.#wasmMemoryObservationCount,
            1,
            'WASM memory observation count',
        );
        if (observedByteLength > this.#lastObservedWasmMemoryByteLength) {
            this.#growthObservationCount = checkedAdd(
                this.#growthObservationCount,
                1,
                'WASM memory growth observation count',
            );
        }
        this.#lastObservedWasmMemoryByteLength = observedByteLength;
        this.#peakWasmMemoryByteLength = Math.max(
            this.#peakWasmMemoryByteLength,
            observedByteLength,
        );
    }
}

const requireSelectedCase = (
    cases: readonly ProductionDesktopBrowserEvaluatorReplayMeasurementCase[],
    selectedCaseIdentifier: string,
): ProductionDesktopBrowserEvaluatorReplayMeasurementCase => {
    const requiredCaseIdentifier =
        requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier(
            selectedCaseIdentifier,
        );
    const matchingCases = cases.filter(
        ({ caseIdentifier }) =>
            requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier(
                caseIdentifier,
            ) === requiredCaseIdentifier,
    );
    if (matchingCases.length !== 1) {
        throw new Error(
            matchingCases.length === 0
                ? `No production evaluator-replay measurement case is registered for ${requiredCaseIdentifier}.`
                : `More than one production evaluator-replay measurement case is registered for ${requiredCaseIdentifier}.`,
        );
    }
    return matchingCases[0];
};

const throwOperationAndCleanupFailures = (
    operationFailure: unknown,
    cleanupFailures: readonly unknown[],
): never => {
    if (cleanupFailures.length === 0) {
        throw operationFailure;
    }
    throw new DesktopBrowserEvaluatorReplayMeasurementCleanupError(
        operationFailure,
        cleanupFailures,
    );
};

export const measureProductionDesktopBrowserEvaluatorReplayCase = async (
    cases: readonly ProductionDesktopBrowserEvaluatorReplayMeasurementCase[],
    selectedCaseIdentifier: string,
): Promise<DesktopBrowserEvaluatorReplayMeasurement> => {
    const selectedCase = requireSelectedCase(cases, selectedCaseIdentifier);
    let session: DesktopBrowserEvaluatorReplayMeasurementWorkerSession;
    try {
        session = await selectedCase.open();
    } catch (error) {
        throw Object.assign(
            new Error(
                `Production evaluator-replay measurement case ${selectedCase.caseIdentifier} could not open verified inputs.`,
            ),
            { cause: error },
        );
    }

    let canonicalCarrierBytes: Uint8Array<ArrayBuffer> | undefined;
    let operationFailed = false;
    let operationFailure: unknown;
    let preparedReplay: PreparedEvaluatorReplay | undefined;
    let result: DesktopBrowserEvaluatorReplayMeasurement | undefined;
    let verifiedReplay: VerifiedEvaluatorReplay | undefined;
    try {
        const recorder = new DesktopBrowserEvaluatorReplayRecorder(
            session.wasmMemory,
            session.evaluatorKeyStoreByteLength,
        );
        const measurementIdentity =
            requireProductionDesktopBrowserMeasurementIdentity(
                session.measurementIdentity,
            );
        const startTime = performance.now();
        preparedReplay = await prepareEvaluatorReplayInClosedWorker({
            acceptedSetupAuthority: session.acceptedSetupAuthority,
            evaluatorKeyStore: session.evaluatorKeyStore,
            kernel: session.kernel,
            options: {
                observeEvaluatorKeyStoreRangeRead: (
                    observation: EvaluatorKeyStoreRangeReadObservation,
                ) => recorder.observeEvaluatorKeyStoreRangeRead(observation),
                yieldControl: () => recorder.yieldControl(),
            },
            verifiedAggregateAuthority: session.verifiedAggregateAuthority,
        });
        canonicalCarrierBytes = preparedReplay.copyCanonicalCarrier();
        const verifiedReplayObject =
            await recorder.ingestCanonicalReplayCarrier(
                canonicalCarrierBytes,
                (bytes) => session.ingestCanonicalReplayCarrier(bytes),
            );
        verifiedReplay = recorder.observeSynchronousOperation(() =>
            preparedReplay?.bind(verifiedReplayObject),
        );
        if (verifiedReplay === undefined) {
            throw new Error(
                'The production evaluator-replay measurement lost its prepared replay before board binding.',
            );
        }
        preparedReplay = undefined;
        const elapsedMilliseconds = performance.now() - startTime;
        await recorder.recordCanonicalReplayCarrierHash(canonicalCarrierBytes);
        result = recorder.finish({
            caseIdentifier: selectedCase.caseIdentifier,
            elapsedMilliseconds,
            measurementIdentity,
        });
    } catch (error) {
        operationFailed = true;
        operationFailure = error;
    }

    const cleanupFailures: unknown[] = [];
    if (preparedReplay !== undefined) {
        try {
            preparedReplay.cancel();
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    if (verifiedReplay !== undefined) {
        try {
            releaseVerifiedEvaluatorReplay(verifiedReplay);
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    canonicalCarrierBytes?.fill(0);
    try {
        await session.close();
    } catch (error) {
        cleanupFailures.push(error);
    }

    if (operationFailed) {
        throwOperationAndCleanupFailures(operationFailure, cleanupFailures);
    }
    if (cleanupFailures.length === 1) {
        throw cleanupFailures[0];
    }
    if (cleanupFailures.length > 1) {
        throw new DesktopBrowserEvaluatorReplayMeasurementCleanupError(
            undefined,
            cleanupFailures,
        );
    }
    if (result === undefined) {
        throw new Error(
            'The production evaluator-replay measurement produced no result.',
        );
    }
    return result;
};
