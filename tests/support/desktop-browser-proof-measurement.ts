const sha512HexPattern = /^[0-9a-f]{128}$/u;
const sha256HexPattern = /^[0-9a-f]{64}$/u;

export const desktopBrowserProofMeasurementConsolePrefix =
    'sealed-lattice-desktop-browser-proof-measurement:';

export type DesktopBrowserProofExecutionKind =
    | 'fresh-generation'
    | 'replay'
    | 'resumed-generation'
    | 'verification';

export type DesktopBrowserProofMeasurementRecord = Readonly<{
    canonicalInputByteLength: number;
    canonicalInputSha512Hex: string;
    canonicalOutputByteLength: number;
    caseIdentifier: string;
    copiedBufferPeakByteLength: number;
    durationMilliseconds: number;
    executionKind: DesktopBrowserProofExecutionKind;
    externalScratchPeakByteLength: number;
    externalScratchReadByteLength: number;
    externalScratchTransactionCount: number;
    externalScratchWriteByteLength: number;
    finishedAtUnixMilliseconds: number;
    fullBufferCopiedByteLength: number;
    fullBufferCopyCount: number;
    observedHostAllocationVolumeByteLength: number;
    javascriptHeapEndByteLength?: number;
    javascriptHeapPeakByteLength?: number;
    javascriptHeapStartByteLength?: number;
    outputSha512Hex: string;
    retainedResidentPeakByteLength: number;
    runOrdinal: number;
    suiteId: string;
    startedAtUnixMilliseconds: number;
    wasmSha256Hex: string;
    wasmLinearMemoryEndByteLength: number;
    wasmLinearMemoryPeakByteLength: number;
    wasmLinearMemoryStartByteLength: number;
}>;

type MemoryReaders = Readonly<{
    externalScratchByteLength?: () => number;
    retainedResidentByteLength?: () => number;
    wasmLinearMemoryByteLength: () => number;
}>;

type MemoryObservation = Readonly<{
    externalScratchByteLength: number;
    javascriptHeapByteLength?: number;
    retainedResidentByteLength: number;
    wasmLinearMemoryByteLength: number;
}>;

type DesktopBrowserProofMeasurement = Readonly<{
    finish(input: {
        canonicalInputByteLength: number;
        canonicalInputSha512Hex: string;
        canonicalOutputByteLength: number;
        copiedBufferPeakByteLength: number;
        externalScratchPeakByteLength: number;
        externalScratchReadByteLength: number;
        externalScratchTransactionCount: number;
        externalScratchWriteByteLength: number;
        fullBufferCopiedByteLength: number;
        fullBufferCopyCount: number;
        observedHostAllocationVolumeByteLength: number;
        outputSha512Hex: string;
    }): DesktopBrowserProofMeasurementRecord;
    sample(): void;
    yieldControl(): Promise<void>;
}>;

const requireNonnegativeSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    if (!Number.isSafeInteger(value) || Number(value) < 0) {
        throw new TypeError(`${fieldName} must be a nonnegative safe integer.`);
    }
    return Number(value);
};

const requirePositiveSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    const number = requireNonnegativeSafeInteger(value, fieldName);
    if (number === 0) {
        throw new TypeError(`${fieldName} must be positive.`);
    }
    return number;
};

const requireFiniteNonnegativeNumber = (
    value: unknown,
    fieldName: string,
): number => {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a nonnegative finite number.`,
        );
    }
    return value;
};

const requireNonemptyIdentifier = (
    value: unknown,
    fieldName: string,
): string => {
    if (
        typeof value !== 'string' ||
        !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(value)
    ) {
        throw new TypeError(`${fieldName} must be a kebab-case identifier.`);
    }
    return value;
};

const executionKinds = new Set<DesktopBrowserProofExecutionKind>([
    'fresh-generation',
    'replay',
    'resumed-generation',
    'verification',
]);

const requireExecutionKind = (
    value: unknown,
): DesktopBrowserProofExecutionKind => {
    if (
        typeof value !== 'string' ||
        !executionKinds.has(value as DesktopBrowserProofExecutionKind)
    ) {
        throw new TypeError(
            'executionKind is not a desktop-browser proof execution kind.',
        );
    }
    return value as DesktopBrowserProofExecutionKind;
};

const optionalNonnegativeSafeInteger = (
    record: Readonly<Record<string, unknown>>,
    fieldName: string,
): number | undefined => {
    const value = record[fieldName];
    return value === undefined
        ? undefined
        : requireNonnegativeSafeInteger(value, fieldName);
};

export const parseDesktopBrowserProofMeasurementRecord = (
    value: unknown,
): DesktopBrowserProofMeasurementRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(
            'The desktop-browser proof measurement must be an object.',
        );
    }
    const record = value as Readonly<Record<string, unknown>>;
    const outputSha512Hex = record.outputSha512Hex;
    if (
        typeof outputSha512Hex !== 'string' ||
        !sha512HexPattern.test(outputSha512Hex)
    ) {
        throw new TypeError(
            'outputSha512Hex must be a lowercase SHA-512 digest.',
        );
    }
    const canonicalInputSha512Hex = record.canonicalInputSha512Hex;
    if (
        typeof canonicalInputSha512Hex !== 'string' ||
        !sha512HexPattern.test(canonicalInputSha512Hex)
    ) {
        throw new TypeError(
            'canonicalInputSha512Hex must be a lowercase SHA-512 digest.',
        );
    }
    const suiteId = record.suiteId;
    if (typeof suiteId !== 'string' || !sha512HexPattern.test(suiteId)) {
        throw new TypeError('suiteId must be a lowercase 64-byte hash.');
    }
    const wasmSha256Hex = record.wasmSha256Hex;
    if (
        typeof wasmSha256Hex !== 'string' ||
        !sha256HexPattern.test(wasmSha256Hex)
    ) {
        throw new TypeError(
            'wasmSha256Hex must be a lowercase SHA-256 digest.',
        );
    }
    const startedAtUnixMilliseconds = requireNonnegativeSafeInteger(
        record.startedAtUnixMilliseconds,
        'startedAtUnixMilliseconds',
    );
    const finishedAtUnixMilliseconds = requireNonnegativeSafeInteger(
        record.finishedAtUnixMilliseconds,
        'finishedAtUnixMilliseconds',
    );
    if (finishedAtUnixMilliseconds < startedAtUnixMilliseconds) {
        throw new TypeError(
            'finishedAtUnixMilliseconds precedes startedAtUnixMilliseconds.',
        );
    }
    const wasmLinearMemoryStartByteLength = requirePositiveSafeInteger(
        record.wasmLinearMemoryStartByteLength,
        'wasmLinearMemoryStartByteLength',
    );
    const wasmLinearMemoryEndByteLength = requirePositiveSafeInteger(
        record.wasmLinearMemoryEndByteLength,
        'wasmLinearMemoryEndByteLength',
    );
    const wasmLinearMemoryPeakByteLength = requirePositiveSafeInteger(
        record.wasmLinearMemoryPeakByteLength,
        'wasmLinearMemoryPeakByteLength',
    );
    if (
        wasmLinearMemoryPeakByteLength < wasmLinearMemoryStartByteLength ||
        wasmLinearMemoryPeakByteLength < wasmLinearMemoryEndByteLength
    ) {
        throw new TypeError(
            'wasmLinearMemoryPeakByteLength is below an endpoint observation.',
        );
    }
    const javascriptHeapStartByteLength = optionalNonnegativeSafeInteger(
        record,
        'javascriptHeapStartByteLength',
    );
    const javascriptHeapEndByteLength = optionalNonnegativeSafeInteger(
        record,
        'javascriptHeapEndByteLength',
    );
    const javascriptHeapPeakByteLength = optionalNonnegativeSafeInteger(
        record,
        'javascriptHeapPeakByteLength',
    );
    const javascriptHeapObservationCount = [
        javascriptHeapStartByteLength,
        javascriptHeapEndByteLength,
        javascriptHeapPeakByteLength,
    ].filter((observation) => observation !== undefined).length;
    if (
        javascriptHeapObservationCount !== 0 &&
        javascriptHeapObservationCount !== 3
    ) {
        throw new TypeError(
            'JavaScript heap observations must be either complete or absent.',
        );
    }
    if (
        javascriptHeapPeakByteLength !== undefined &&
        (javascriptHeapPeakByteLength < (javascriptHeapStartByteLength ?? 0) ||
            javascriptHeapPeakByteLength < (javascriptHeapEndByteLength ?? 0))
    ) {
        throw new TypeError(
            'javascriptHeapPeakByteLength is below an endpoint observation.',
        );
    }
    const copiedBufferPeakByteLength = requireNonnegativeSafeInteger(
        record.copiedBufferPeakByteLength,
        'copiedBufferPeakByteLength',
    );
    const externalScratchPeakByteLength = requireNonnegativeSafeInteger(
        record.externalScratchPeakByteLength,
        'externalScratchPeakByteLength',
    );
    const externalScratchReadByteLength = requireNonnegativeSafeInteger(
        record.externalScratchReadByteLength,
        'externalScratchReadByteLength',
    );
    const externalScratchTransactionCount = requireNonnegativeSafeInteger(
        record.externalScratchTransactionCount,
        'externalScratchTransactionCount',
    );
    const externalScratchWriteByteLength = requireNonnegativeSafeInteger(
        record.externalScratchWriteByteLength,
        'externalScratchWriteByteLength',
    );
    if (
        externalScratchTransactionCount === 0 &&
        (externalScratchPeakByteLength !== 0 ||
            externalScratchReadByteLength !== 0 ||
            externalScratchWriteByteLength !== 0)
    ) {
        throw new TypeError(
            'External-scratch bytes require at least one observed transaction.',
        );
    }
    const fullBufferCopiedByteLength = requireNonnegativeSafeInteger(
        record.fullBufferCopiedByteLength,
        'fullBufferCopiedByteLength',
    );
    const fullBufferCopyCount = requireNonnegativeSafeInteger(
        record.fullBufferCopyCount,
        'fullBufferCopyCount',
    );
    if (
        (fullBufferCopyCount === 0) !== (fullBufferCopiedByteLength === 0) ||
        (fullBufferCopyCount === 0) !== (copiedBufferPeakByteLength === 0) ||
        fullBufferCopiedByteLength < copiedBufferPeakByteLength
    ) {
        throw new TypeError(
            'Full-buffer copy count, volume, and peak are inconsistent.',
        );
    }

    return Object.freeze({
        canonicalInputByteLength: requireNonnegativeSafeInteger(
            record.canonicalInputByteLength,
            'canonicalInputByteLength',
        ),
        canonicalInputSha512Hex,
        canonicalOutputByteLength: requireNonnegativeSafeInteger(
            record.canonicalOutputByteLength,
            'canonicalOutputByteLength',
        ),
        caseIdentifier: requireNonemptyIdentifier(
            record.caseIdentifier,
            'caseIdentifier',
        ),
        copiedBufferPeakByteLength,
        durationMilliseconds: requireFiniteNonnegativeNumber(
            record.durationMilliseconds,
            'durationMilliseconds',
        ),
        executionKind: requireExecutionKind(record.executionKind),
        externalScratchPeakByteLength,
        externalScratchReadByteLength,
        externalScratchTransactionCount,
        externalScratchWriteByteLength,
        finishedAtUnixMilliseconds,
        fullBufferCopiedByteLength,
        fullBufferCopyCount,
        observedHostAllocationVolumeByteLength: requireNonnegativeSafeInteger(
            record.observedHostAllocationVolumeByteLength,
            'observedHostAllocationVolumeByteLength',
        ),
        ...(javascriptHeapEndByteLength === undefined
            ? {}
            : { javascriptHeapEndByteLength }),
        ...(javascriptHeapPeakByteLength === undefined
            ? {}
            : { javascriptHeapPeakByteLength }),
        ...(javascriptHeapStartByteLength === undefined
            ? {}
            : { javascriptHeapStartByteLength }),
        outputSha512Hex,
        retainedResidentPeakByteLength: requireNonnegativeSafeInteger(
            record.retainedResidentPeakByteLength,
            'retainedResidentPeakByteLength',
        ),
        runOrdinal: requirePositiveSafeInteger(record.runOrdinal, 'runOrdinal'),
        suiteId,
        startedAtUnixMilliseconds,
        wasmSha256Hex,
        wasmLinearMemoryEndByteLength,
        wasmLinearMemoryPeakByteLength,
        wasmLinearMemoryStartByteLength,
    });
};

const readJavaScriptHeapByteLength = (): number | undefined => {
    const memory = (
        performance as Performance & {
            readonly memory?: Readonly<{ usedJSHeapSize?: unknown }>;
        }
    ).memory;
    const usedHeapSize = memory?.usedJSHeapSize;
    return Number.isSafeInteger(usedHeapSize) && Number(usedHeapSize) >= 0
        ? Number(usedHeapSize)
        : undefined;
};

const readObservation = (readers: MemoryReaders): MemoryObservation => {
    const javascriptHeapByteLength = readJavaScriptHeapByteLength();
    return {
        externalScratchByteLength: requireNonnegativeSafeInteger(
            readers.externalScratchByteLength?.() ?? 0,
            'externalScratchByteLength',
        ),
        ...(javascriptHeapByteLength === undefined
            ? {}
            : { javascriptHeapByteLength }),
        retainedResidentByteLength: requireNonnegativeSafeInteger(
            readers.retainedResidentByteLength?.() ?? 0,
            'retainedResidentByteLength',
        ),
        wasmLinearMemoryByteLength: requirePositiveSafeInteger(
            readers.wasmLinearMemoryByteLength(),
            'wasmLinearMemoryByteLength',
        ),
    };
};

const yieldBrowserTurn = (): Promise<void> =>
    new Promise((resolve) => {
        setTimeout(resolve, 0);
    });

export const beginDesktopBrowserProofMeasurement = (input: {
    caseIdentifier: string;
    /**
     * A dedicated worker can return the parsed record to its owning test and
     * let that one reporter-visible realm emit it. This prevents the same
     * operation from being recorded twice when browser tooling forwards
     * worker console output.
     */
    emitConsoleEvent?: boolean;
    executionKind: DesktopBrowserProofExecutionKind;
    memoryReaders: MemoryReaders;
    runOrdinal: number;
    suiteId: string;
    wasmSha256Hex: string;
}): DesktopBrowserProofMeasurement => {
    const caseIdentifier = requireNonemptyIdentifier(
        input.caseIdentifier,
        'caseIdentifier',
    );
    const executionKind = requireExecutionKind(input.executionKind);
    const runOrdinal = requirePositiveSafeInteger(
        input.runOrdinal,
        'runOrdinal',
    );
    const suiteId = input.suiteId;
    if (!sha512HexPattern.test(suiteId)) {
        throw new TypeError('suiteId must be a lowercase 64-byte hash.');
    }
    const wasmSha256Hex = input.wasmSha256Hex;
    if (!sha256HexPattern.test(wasmSha256Hex)) {
        throw new TypeError(
            'wasmSha256Hex must be a lowercase SHA-256 digest.',
        );
    }
    const startedAtUnixMilliseconds = Date.now();
    const startedAtHighResolutionMilliseconds = performance.now();
    const start = readObservation(input.memoryReaders);
    let end = start;
    let externalScratchPeakByteLength = start.externalScratchByteLength;
    let javascriptHeapPeakByteLength = start.javascriptHeapByteLength;
    let retainedResidentPeakByteLength = start.retainedResidentByteLength;
    let wasmLinearMemoryPeakByteLength = start.wasmLinearMemoryByteLength;
    let finished = false;

    const sample = (): void => {
        if (finished) {
            throw new Error(
                'The desktop-browser proof measurement is already finished.',
            );
        }
        end = readObservation(input.memoryReaders);
        externalScratchPeakByteLength = Math.max(
            externalScratchPeakByteLength,
            end.externalScratchByteLength,
        );
        retainedResidentPeakByteLength = Math.max(
            retainedResidentPeakByteLength,
            end.retainedResidentByteLength,
        );
        wasmLinearMemoryPeakByteLength = Math.max(
            wasmLinearMemoryPeakByteLength,
            end.wasmLinearMemoryByteLength,
        );
        if (end.javascriptHeapByteLength !== undefined) {
            javascriptHeapPeakByteLength = Math.max(
                javascriptHeapPeakByteLength ?? 0,
                end.javascriptHeapByteLength,
            );
        }
    };

    return Object.freeze({
        finish: (finishInput) => {
            sample();
            finished = true;
            const finishedAtUnixMilliseconds = Date.now();
            const record = parseDesktopBrowserProofMeasurementRecord({
                canonicalInputByteLength: requireNonnegativeSafeInteger(
                    finishInput.canonicalInputByteLength,
                    'canonicalInputByteLength',
                ),
                canonicalInputSha512Hex: finishInput.canonicalInputSha512Hex,
                canonicalOutputByteLength: requireNonnegativeSafeInteger(
                    finishInput.canonicalOutputByteLength,
                    'canonicalOutputByteLength',
                ),
                caseIdentifier,
                copiedBufferPeakByteLength: requireNonnegativeSafeInteger(
                    finishInput.copiedBufferPeakByteLength,
                    'copiedBufferPeakByteLength',
                ),
                durationMilliseconds:
                    performance.now() - startedAtHighResolutionMilliseconds,
                executionKind,
                externalScratchPeakByteLength: Math.max(
                    externalScratchPeakByteLength,
                    requireNonnegativeSafeInteger(
                        finishInput.externalScratchPeakByteLength,
                        'externalScratchPeakByteLength',
                    ),
                ),
                externalScratchReadByteLength:
                    finishInput.externalScratchReadByteLength,
                externalScratchTransactionCount:
                    finishInput.externalScratchTransactionCount,
                externalScratchWriteByteLength:
                    finishInput.externalScratchWriteByteLength,
                finishedAtUnixMilliseconds,
                fullBufferCopiedByteLength:
                    finishInput.fullBufferCopiedByteLength,
                fullBufferCopyCount: finishInput.fullBufferCopyCount,
                observedHostAllocationVolumeByteLength:
                    finishInput.observedHostAllocationVolumeByteLength,
                ...(start.javascriptHeapByteLength === undefined ||
                end.javascriptHeapByteLength === undefined ||
                javascriptHeapPeakByteLength === undefined
                    ? {}
                    : {
                          javascriptHeapEndByteLength:
                              end.javascriptHeapByteLength,
                          javascriptHeapPeakByteLength,
                          javascriptHeapStartByteLength:
                              start.javascriptHeapByteLength,
                      }),
                outputSha512Hex: finishInput.outputSha512Hex,
                retainedResidentPeakByteLength,
                runOrdinal,
                suiteId,
                startedAtUnixMilliseconds,
                wasmSha256Hex,
                wasmLinearMemoryEndByteLength: end.wasmLinearMemoryByteLength,
                wasmLinearMemoryPeakByteLength,
                wasmLinearMemoryStartByteLength:
                    start.wasmLinearMemoryByteLength,
            });
            if (input.emitConsoleEvent !== false) {
                console.info(
                    `${desktopBrowserProofMeasurementConsolePrefix}${JSON.stringify(record)}`,
                );
            }
            return record;
        },
        sample,
        yieldControl: async () => {
            sample();
            await yieldBrowserTurn();
            sample();
        },
    });
};

export const sha512Hex = async (bytes: Uint8Array): Promise<string> => {
    const digest = await crypto.subtle.digest(
        'SHA-512',
        Uint8Array.from(bytes),
    );
    return Array.from(new Uint8Array(digest), (byte) =>
        byte.toString(16).padStart(2, '0'),
    ).join('');
};
