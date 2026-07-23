const maximumUnsigned64 = (1n << 64n) - 1n;
const requiredGuardSampleIntervalMilliseconds = 100n;
const maximumGuardTelemetryGapMilliseconds = 500n;
const hash512HexPattern = /^[0-9a-f]{128}$/u;

export const proofBackendBakeoffSchedule = [
    { backend: 'packed-deep-fri', sampleOrdinal: 1 },
    { backend: 'sumcheck-class', sampleOrdinal: 1 },
    { backend: 'packed-deep-fri', sampleOrdinal: 2 },
    { backend: 'sumcheck-class', sampleOrdinal: 2 },
    { backend: 'packed-deep-fri', sampleOrdinal: 3 },
    { backend: 'sumcheck-class', sampleOrdinal: 3 },
] as const;

export type ProofBackendName =
    (typeof proofBackendBakeoffSchedule)[number]['backend'];

export const proofBackendBakeoffCustodyModel =
    'bounded-external-storage-replay' as const;
export const proofBackendBakeoffCustodySchemaIdentifier =
    'bounded-external-storage-replay-v1' as const;
export const proofBackendBakeoffCustodySchemaVersion = 1 as const;

type ProofBackendBakeoffCustodyModel = typeof proofBackendBakeoffCustodyModel;

type ProofBackendBakeoffExecutionContract = Readonly<{
    backend: ProofBackendName;
    custodyModel: ProofBackendBakeoffCustodyModel;
    custodySchemaIdentifier: typeof proofBackendBakeoffCustodySchemaIdentifier;
    custodySchemaVersion: typeof proofBackendBakeoffCustodySchemaVersion;
    proofPhysicalObjectCount: 1;
    sourcePhysicalObjectCount: 8;
}>;

// Each arm is measured against the same exact eight replay-source objects and
// one canonical-proof object. Raw format version two binds this independently
// selected contract before a sample can participate in aggregation.
export const proofBackendBakeoffExecutionContracts = {
    'packed-deep-fri': {
        backend: 'packed-deep-fri',
        custodyModel: proofBackendBakeoffCustodyModel,
        custodySchemaIdentifier: proofBackendBakeoffCustodySchemaIdentifier,
        custodySchemaVersion: proofBackendBakeoffCustodySchemaVersion,
        proofPhysicalObjectCount: 1,
        sourcePhysicalObjectCount: 8,
    },
    'sumcheck-class': {
        backend: 'sumcheck-class',
        custodyModel: proofBackendBakeoffCustodyModel,
        custodySchemaIdentifier: proofBackendBakeoffCustodySchemaIdentifier,
        custodySchemaVersion: proofBackendBakeoffCustodySchemaVersion,
        proofPhysicalObjectCount: 1,
        sourcePhysicalObjectCount: 8,
    },
} as const satisfies Record<
    ProofBackendName,
    ProofBackendBakeoffExecutionContract
>;

type ParsedProofBackendBakeoffMeasurements = Readonly<{
    backend: ProofBackendName;
    canonicalProofByteLength: bigint;
    elapsedNanoseconds: bigint;
    externalCommittedTransactionCount: bigint;
    externalIoByteLength: bigint;
    externalReadByteLength: bigint;
    externalWrittenByteLength: bigint;
    frozenInputIdentityShake256Hex: string;
    operationFinishedAtUnixMilliseconds: bigint;
    operationStartedAtUnixMilliseconds: bigint;
    proofShake256Hex: string;
    sampleOrdinal: 1 | 2 | 3;
}>;

type AuditedHistoricalProofBackendBakeoffResult =
    ParsedProofBackendBakeoffMeasurements &
        Readonly<{
            formatVersion: 1;
        }>;

type ValidatedProofBackendBakeoffResult =
    ParsedProofBackendBakeoffMeasurements &
        Readonly<{
            custodyCleanupCompleted: true;
            custodyModel: ProofBackendBakeoffCustodyModel;
            custodySchemaIdentifier: typeof proofBackendBakeoffCustodySchemaIdentifier;
            custodySchemaVersion: typeof proofBackendBakeoffCustodySchemaVersion;
            formatVersion: 2;
            proofPhysicalObjectCount: 1n;
            sourcePhysicalObjectCount: 8n;
        }>;

type ProofBackendBakeoffOperationMemory = Readonly<{
    baselineProcessTreeResidentMemoryByteLength: bigint;
    inWindowSampleCount: number;
    peakProcessTreeResidentMemoryByteLength: bigint;
    resourceSampleIntervalMilliseconds: bigint;
}>;

type ValidatedProofBackendBakeoffSample = Readonly<{
    baselineProcessTreeResidentMemoryByteLength: bigint;
    peakProcessTreeResidentMemoryByteLength: bigint;
    result: ValidatedProofBackendBakeoffResult;
}>;

type ProofBackendBakeoffArmResult = Readonly<{
    backend: ProofBackendName;
    canonicalProofByteLength: bigint;
    custodyCleanupCompleted: true;
    custodyModel: ProofBackendBakeoffCustodyModel;
    custodySchemaIdentifier: typeof proofBackendBakeoffCustodySchemaIdentifier;
    custodySchemaVersion: typeof proofBackendBakeoffCustodySchemaVersion;
    externalCommittedTransactionCount: bigint;
    externalIoByteLength: bigint;
    externalReadByteLength: bigint;
    externalWrittenByteLength: bigint;
    frozenInputIdentityShake256Hex: string;
    maximumBaselineProcessTreeResidentMemoryByteLength: bigint;
    maximumPeakProcessTreeResidentMemoryByteLength: bigint;
    medianElapsedNanoseconds: bigint;
    proofPhysicalObjectCount: 1n;
    proofShake256Hex: string;
    sampleCount: 3;
    sourcePhysicalObjectCount: 8n;
}>;

type ProofBackendBakeoffMetricName =
    | 'elapsed-time'
    | 'external-io'
    | 'external-transactions'
    | 'peak-resident-memory'
    | 'proof-bytes';

export const proofBackendBakeoffEligibleMetrics = [
    'proof-bytes',
    'elapsed-time',
    'peak-resident-memory',
    'external-io',
    'external-transactions',
] as const satisfies readonly ProofBackendBakeoffMetricName[];

export const proofBackendBakeoffExcludedMetrics =
    [] as const satisfies readonly ProofBackendBakeoffMetricName[];

type ProofBackendBakeoffMetricWinner = ProofBackendName | 'neutral';

type ProofBackendBakeoffDecision = Readonly<{
    custodyModel: ProofBackendBakeoffCustodyModel;
    custodySchemaIdentifier: typeof proofBackendBakeoffCustodySchemaIdentifier;
    custodySchemaVersion: typeof proofBackendBakeoffCustodySchemaVersion;
    eligibleMetrics: typeof proofBackendBakeoffEligibleMetrics;
    excludedMetrics: typeof proofBackendBakeoffExcludedMetrics;
    metricWinners: Readonly<
        Record<ProofBackendBakeoffMetricName, ProofBackendBakeoffMetricWinner>
    >;
    outcome: 'ambiguous' | 'selected';
    packedDeepFriWinCount: number;
    selectedBackend?: ProofBackendName;
    sumcheckClassWinCount: number;
}>;

type JsonObject = Readonly<Record<string, unknown>>;

const requireJsonObject = (value: unknown, name: string): JsonObject => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${name} must be a JSON object.`);
    }
    return value as JsonObject;
};

export const parseCanonicalUnsigned64Decimal = (
    value: unknown,
    fieldName: string,
): bigint => {
    if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
        throw new Error(`${fieldName} must be a canonical decimal u64 string.`);
    }
    const parsed = BigInt(value);
    if (parsed > maximumUnsigned64) {
        throw new Error(`${fieldName} exceeds u64.`);
    }
    return parsed;
};

const parseGuardUnsigned64 = (value: unknown, fieldName: string): bigint => {
    if (typeof value === 'string') {
        return parseCanonicalUnsigned64Decimal(value, fieldName);
    }
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0
    ) {
        throw new Error(
            `${fieldName} must be a safe unsigned JSON integer or canonical decimal u64 string.`,
        );
    }
    return BigInt(value);
};

const requireUnsigned64 = (value: bigint, fieldName: string): void => {
    if (value < 0n || value > maximumUnsigned64) {
        throw new Error(`${fieldName} must fit u64.`);
    }
};

export const checkedAddUnsigned64 = (
    left: bigint,
    right: bigint,
    fieldName: string,
): bigint => {
    requireUnsigned64(left, `${fieldName} left operand`);
    requireUnsigned64(right, `${fieldName} right operand`);
    const sum = left + right;
    if (sum > maximumUnsigned64) {
        throw new Error(`${fieldName} exceeds u64.`);
    }
    return sum;
};

const requireHash512Hex = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !hash512HexPattern.test(value)) {
        throw new Error(
            `${fieldName} must be a lowercase 64-byte hexadecimal digest.`,
        );
    }
    return value;
};

const requireBackend = (value: unknown): ProofBackendName => {
    if (value === 'packed-deep-fri' || value === 'sumcheck-class') {
        return value;
    }
    throw new Error('backend is not a bakeoff backend.');
};

const requireCustodyModel = (
    value: unknown,
): ProofBackendBakeoffCustodyModel => {
    if (value === proofBackendBakeoffCustodyModel) {
        return value;
    }
    throw new Error('custodyModel must be bounded-external-storage-replay.');
};

const requireExactString = <Expected extends string>(
    value: unknown,
    expected: Expected,
    fieldName: string,
): Expected => {
    if (value !== expected) {
        throw new Error(`${fieldName} must be ${expected}.`);
    }
    return expected;
};

const requireExactNumber = <Expected extends number>(
    value: unknown,
    expected: Expected,
    fieldName: string,
): Expected => {
    if (value !== expected) {
        throw new Error(`${fieldName} must be ${expected}.`);
    }
    return expected;
};

const requireSampleOrdinal = (value: unknown): 1 | 2 | 3 => {
    if (value === 1 || value === 2 || value === 3) {
        return value;
    }
    throw new Error('sampleOrdinal must be one, two, or three.');
};

const maximum = (values: readonly bigint[]): bigint => {
    const first = values[0];
    if (first === undefined) {
        throw new Error('Cannot find a maximum of an empty collection.');
    }
    return values
        .slice(1)
        .reduce((current, value) => (value > current ? value : current), first);
};

const parseProofBackendBakeoffMeasurements = (
    record: JsonObject,
): ParsedProofBackendBakeoffMeasurements => {
    const backend = requireBackend(record.backend);
    const sampleOrdinal = requireSampleOrdinal(record.sampleOrdinal);
    const frozenInputIdentityShake256Hex = requireHash512Hex(
        record.frozenInputIdentityShake256Hex,
        'frozenInputIdentityShake256Hex',
    );
    const proofShake256Hex = requireHash512Hex(
        record.proofShake256Hex,
        'proofShake256Hex',
    );
    const elapsedNanoseconds = parseCanonicalUnsigned64Decimal(
        record.elapsedNanosecondsDecimal,
        'elapsedNanosecondsDecimal',
    );
    const canonicalProofByteLength = parseCanonicalUnsigned64Decimal(
        record.canonicalProofByteLengthDecimal,
        'canonicalProofByteLengthDecimal',
    );
    if (elapsedNanoseconds === 0n || canonicalProofByteLength === 0n) {
        throw new Error(
            'Elapsed time and canonical proof bytes must be positive.',
        );
    }
    const externalReadByteLength = parseCanonicalUnsigned64Decimal(
        record.externalReadByteLengthDecimal,
        'externalReadByteLengthDecimal',
    );
    const externalWrittenByteLength = parseCanonicalUnsigned64Decimal(
        record.externalWrittenByteLengthDecimal,
        'externalWrittenByteLengthDecimal',
    );
    const externalIoByteLength = checkedAddUnsigned64(
        externalReadByteLength,
        externalWrittenByteLength,
        'externalIoByteLength',
    );
    const externalCommittedTransactionCount = parseCanonicalUnsigned64Decimal(
        record.externalCommittedTransactionCountDecimal,
        'externalCommittedTransactionCountDecimal',
    );
    const operationStartedAtUnixMilliseconds = parseGuardUnsigned64(
        record.operationStartedAtUnixMilliseconds,
        'operationStartedAtUnixMilliseconds',
    );
    const operationFinishedAtUnixMilliseconds = parseGuardUnsigned64(
        record.operationFinishedAtUnixMilliseconds,
        'operationFinishedAtUnixMilliseconds',
    );
    if (
        operationFinishedAtUnixMilliseconds < operationStartedAtUnixMilliseconds
    ) {
        throw new Error('The bakeoff result operation window is reversed.');
    }

    return {
        backend,
        canonicalProofByteLength,
        elapsedNanoseconds,
        externalCommittedTransactionCount,
        externalIoByteLength,
        externalReadByteLength,
        externalWrittenByteLength,
        frozenInputIdentityShake256Hex,
        operationFinishedAtUnixMilliseconds,
        operationStartedAtUnixMilliseconds,
        proofShake256Hex,
        sampleOrdinal,
    };
};

// Format version one is retained solely so the immutable research evidence can
// still be decoded for audit. It carries no custody-schema or cleanup binding
// and cannot be promoted into a sample eligible for backend selection.
export const auditHistoricalProofBackendBakeoffResult = (
    input: unknown,
): AuditedHistoricalProofBackendBakeoffResult => {
    const record = requireJsonObject(input, 'Historical bakeoff result');
    requireExactNumber(record.formatVersion, 1, 'formatVersion');
    return {
        ...parseProofBackendBakeoffMeasurements(record),
        formatVersion: 1,
    };
};

export const validateProofBackendBakeoffResult = (
    input: unknown,
): ValidatedProofBackendBakeoffResult => {
    const record = requireJsonObject(input, 'Bakeoff result');
    if (record.formatVersion === 1) {
        throw new Error(
            'Format-version-one bakeoff results are historical audit evidence and are ineligible for backend selection.',
        );
    }
    requireExactNumber(record.formatVersion, 2, 'formatVersion');
    const custodyModel = requireCustodyModel(record.custodyModel);
    const custodySchemaIdentifier = requireExactString(
        record.custodySchemaIdentifier,
        proofBackendBakeoffCustodySchemaIdentifier,
        'custodySchemaIdentifier',
    );
    const custodySchemaVersion = requireExactNumber(
        record.custodySchemaVersion,
        proofBackendBakeoffCustodySchemaVersion,
        'custodySchemaVersion',
    );
    if (record.custodyCleanupCompleted !== true) {
        throw new Error('custodyCleanupCompleted must be true.');
    }
    const sourcePhysicalObjectCount = parseCanonicalUnsigned64Decimal(
        record.sourcePhysicalObjectCountDecimal,
        'sourcePhysicalObjectCountDecimal',
    );
    const proofPhysicalObjectCount = parseCanonicalUnsigned64Decimal(
        record.proofPhysicalObjectCountDecimal,
        'proofPhysicalObjectCountDecimal',
    );
    if (sourcePhysicalObjectCount !== 8n) {
        throw new Error('sourcePhysicalObjectCountDecimal must be eight.');
    }
    if (proofPhysicalObjectCount !== 1n) {
        throw new Error('proofPhysicalObjectCountDecimal must be one.');
    }
    const measurements = parseProofBackendBakeoffMeasurements(record);
    for (const [fieldName, value] of [
        ['externalReadByteLengthDecimal', measurements.externalReadByteLength],
        [
            'externalWrittenByteLengthDecimal',
            measurements.externalWrittenByteLength,
        ],
        [
            'externalCommittedTransactionCountDecimal',
            measurements.externalCommittedTransactionCount,
        ],
    ] as const) {
        if (value === 0n) {
            throw new Error(`${fieldName} must be measured and positive.`);
        }
    }
    return {
        ...measurements,
        custodyCleanupCompleted: true,
        custodyModel,
        custodySchemaIdentifier,
        custodySchemaVersion,
        formatVersion: 2,
        proofPhysicalObjectCount: 1n,
        sourcePhysicalObjectCount: 8n,
    };
};

export const extractProofBackendBakeoffOperationMemory = (input: {
    readonly guardJsonLines: string;
    readonly operationFinishedAtUnixMilliseconds: bigint;
    readonly operationStartedAtUnixMilliseconds: bigint;
}): ProofBackendBakeoffOperationMemory => {
    requireUnsigned64(
        input.operationStartedAtUnixMilliseconds,
        'operationStartedAtUnixMilliseconds',
    );
    requireUnsigned64(
        input.operationFinishedAtUnixMilliseconds,
        'operationFinishedAtUnixMilliseconds',
    );
    if (
        input.operationFinishedAtUnixMilliseconds <
        input.operationStartedAtUnixMilliseconds
    ) {
        throw new Error('The bakeoff operation window is reversed.');
    }
    if (typeof input.guardJsonLines !== 'string') {
        throw new Error('guardJsonLines must be a string.');
    }

    const records = input.guardJsonLines
        .split(/\r?\n/u)
        .filter((line) => line.length !== 0)
        .map((line, lineIndex) => {
            let parsed: unknown;
            try {
                parsed = JSON.parse(line) as unknown;
            } catch (error) {
                throw Object.assign(
                    new Error(
                        `Process-memory guard line ${lineIndex + 1} is not valid JSON.`,
                    ),
                    { cause: error },
                );
            }
            const record = requireJsonObject(
                parsed,
                `Process-memory guard line ${lineIndex + 1}`,
            );
            return {
                elapsedMilliseconds: parseGuardUnsigned64(
                    record.elapsedMilliseconds,
                    `Process-memory guard line ${lineIndex + 1} elapsedMilliseconds`,
                ),
                record,
                recordedAtUnixMilliseconds: parseGuardUnsigned64(
                    record.recordedAtUnixMilliseconds,
                    `Process-memory guard line ${lineIndex + 1} recordedAtUnixMilliseconds`,
                ),
                sequence: parseGuardUnsigned64(
                    record.sequence,
                    `Process-memory guard line ${lineIndex + 1} sequence`,
                ),
            };
        });
    if (records.length === 0) {
        throw new Error('Process-memory guard telemetry is empty.');
    }
    for (const [recordIndex, current] of records.entries()) {
        if (current.sequence !== BigInt(recordIndex)) {
            throw new Error(
                'Process-memory guard telemetry sequence must start at zero and remain contiguous.',
            );
        }
        if (recordIndex === 0) {
            continue;
        }
        const previous = records[recordIndex - 1];
        if (previous === undefined) {
            throw new Error('Process-memory guard telemetry indexing failed.');
        }
        if (current.elapsedMilliseconds < previous.elapsedMilliseconds) {
            throw new Error(
                'Process-memory guard telemetry elapsed time must be nondecreasing.',
            );
        }
        if (
            current.recordedAtUnixMilliseconds <
            previous.recordedAtUnixMilliseconds
        ) {
            throw new Error(
                'Process-memory guard telemetry wall time must be nondecreasing.',
            );
        }
    }
    const guardStartedRecord = records[0];
    const childStartedRecord = records[1];
    const childExitedRecord = records[records.length - 1];
    if (
        guardStartedRecord?.record.eventType !== 'guard-started' ||
        childStartedRecord?.record.eventType !== 'child-started' ||
        childExitedRecord?.record.eventType !== 'child-exited' ||
        records
            .slice(2, -1)
            .some(({ record }) => record.eventType !== 'resource-sample')
    ) {
        throw new Error(
            'Process-memory guard telemetry must contain one contiguous guard-started, child-started, resource-sample, and child-exited lifecycle.',
        );
    }
    if (
        input.operationStartedAtUnixMilliseconds <
        childStartedRecord.recordedAtUnixMilliseconds
    ) {
        throw new Error(
            'The bakeoff operation must start inside the guarded child lifecycle.',
        );
    }
    if (
        input.operationFinishedAtUnixMilliseconds >
        childExitedRecord.recordedAtUnixMilliseconds
    ) {
        throw new Error(
            'The bakeoff operation must finish inside the guarded child lifecycle.',
        );
    }
    const terminalRecord = childExitedRecord.record;
    if (
        terminalRecord.memoryEvidence !== 'completed' ||
        terminalRecord.terminationClassification !== 'completed' ||
        terminalRecord.exitCode !== 0
    ) {
        throw new Error(
            'Process-memory guard telemetry lacks a terminal completed child-exited record.',
        );
    }
    const resourceSampleIntervalMilliseconds = parseGuardUnsigned64(
        guardStartedRecord.record.resourceSampleIntervalMilliseconds,
        'resourceSampleIntervalMilliseconds',
    );
    if (
        resourceSampleIntervalMilliseconds !==
        requiredGuardSampleIntervalMilliseconds
    ) {
        throw new Error(
            'Process-memory guard sampling cadence must be exactly 100 milliseconds.',
        );
    }
    if (guardStartedRecord.record.aggregateProcessTreeMemoryLimit !== true) {
        throw new Error(
            'Process-memory guard telemetry must cover the aggregate process tree.',
        );
    }

    const samples = records
        .filter(({ record }) => record.eventType === 'resource-sample')
        .map(
            (
                {
                    elapsedMilliseconds,
                    record,
                    recordedAtUnixMilliseconds,
                    sequence,
                },
                sampleIndex,
            ) => {
                if (record.sampleError !== null) {
                    throw new Error(
                        `Process-memory guard resource sample ${sampleIndex + 1} must explicitly report no sample error.`,
                    );
                }
                if (record.confirmedMemoryLimitViolation !== false) {
                    throw new Error(
                        `Process-memory guard resource sample ${sampleIndex + 1} must explicitly report no memory-limit violation.`,
                    );
                }
                const processTreeResidentMemoryByteLength =
                    parseGuardUnsigned64(
                        record.processTreeResidentMemoryBytes,
                        `resource sample ${sampleIndex + 1} processTreeResidentMemoryBytes`,
                    );
                if (processTreeResidentMemoryByteLength === 0n) {
                    throw new Error(
                        `Process-memory guard resource sample ${sampleIndex + 1} resident memory must be positive.`,
                    );
                }
                return {
                    elapsedMilliseconds,
                    processTreeResidentMemoryByteLength,
                    recordedAtUnixMilliseconds,
                    sequence,
                };
            },
        );
    const baselineSamples = samples.filter(
        (sample) =>
            sample.recordedAtUnixMilliseconds <
            input.operationStartedAtUnixMilliseconds,
    );
    const baselineSample = baselineSamples[baselineSamples.length - 1];
    if (baselineSample === undefined) {
        throw new Error(
            'Process-memory guard telemetry lacks a pre-operation resident baseline.',
        );
    }
    if (
        input.operationStartedAtUnixMilliseconds -
            baselineSample.recordedAtUnixMilliseconds >
        maximumGuardTelemetryGapMilliseconds
    ) {
        throw new Error(
            'Process-memory guard telemetry does not cover the operation start within 500 milliseconds.',
        );
    }
    const inWindowSamples = samples.filter(
        (sample) =>
            sample.recordedAtUnixMilliseconds >=
                input.operationStartedAtUnixMilliseconds &&
            sample.recordedAtUnixMilliseconds <=
                input.operationFinishedAtUnixMilliseconds,
    );
    if (inWindowSamples.length === 0) {
        throw new Error(
            'Process-memory guard telemetry lacks an in-window resident sample.',
        );
    }
    const firstInWindowSample = inWindowSamples[0];
    const lastInWindowSample = inWindowSamples[inWindowSamples.length - 1];
    if (firstInWindowSample === undefined || lastInWindowSample === undefined) {
        throw new Error(
            'Process-memory guard in-window sample indexing failed.',
        );
    }
    if (firstInWindowSample.sequence <= baselineSample.sequence) {
        throw new Error(
            'Process-memory guard operation-window samples are not in telemetry order.',
        );
    }
    if (
        firstInWindowSample.recordedAtUnixMilliseconds -
            input.operationStartedAtUnixMilliseconds >
        maximumGuardTelemetryGapMilliseconds
    ) {
        throw new Error(
            'Process-memory guard telemetry does not cover the operation start within 500 milliseconds.',
        );
    }
    if (
        input.operationFinishedAtUnixMilliseconds -
            lastInWindowSample.recordedAtUnixMilliseconds >
        maximumGuardTelemetryGapMilliseconds
    ) {
        throw new Error(
            'Process-memory guard telemetry does not cover the operation finish within 500 milliseconds.',
        );
    }
    const operationWindowSamples = [baselineSample, ...inWindowSamples];
    for (
        let sampleIndex = 1;
        sampleIndex < operationWindowSamples.length;
        sampleIndex += 1
    ) {
        const previous = operationWindowSamples[sampleIndex - 1];
        const current = operationWindowSamples[sampleIndex];
        if (previous === undefined || current === undefined) {
            throw new Error(
                'Process-memory guard operation-window sample indexing failed.',
            );
        }
        if (
            current.elapsedMilliseconds - previous.elapsedMilliseconds >
            maximumGuardTelemetryGapMilliseconds
        ) {
            throw new Error(
                'Process-memory guard telemetry contains an operation-window gap greater than 500 milliseconds.',
            );
        }
    }

    return {
        baselineProcessTreeResidentMemoryByteLength:
            baselineSample.processTreeResidentMemoryByteLength,
        inWindowSampleCount: inWindowSamples.length,
        peakProcessTreeResidentMemoryByteLength: maximum(
            inWindowSamples.map(
                (sample) => sample.processTreeResidentMemoryByteLength,
            ),
        ),
        resourceSampleIntervalMilliseconds,
    };
};

export const validateProofBackendBakeoffSample = (input: {
    readonly executionContract: ProofBackendBakeoffExecutionContract;
    readonly guardJsonLines: string;
    readonly result: unknown;
}): ValidatedProofBackendBakeoffSample => {
    const result = validateProofBackendBakeoffResult(input.result);
    const contractBackend = requireBackend(input.executionContract.backend);
    const contractCustodyModel = requireCustodyModel(
        input.executionContract.custodyModel,
    );
    const contractCustodySchemaIdentifier = requireExactString(
        input.executionContract.custodySchemaIdentifier,
        proofBackendBakeoffCustodySchemaIdentifier,
        'executionContract.custodySchemaIdentifier',
    );
    const contractCustodySchemaVersion = requireExactNumber(
        input.executionContract.custodySchemaVersion,
        proofBackendBakeoffCustodySchemaVersion,
        'executionContract.custodySchemaVersion',
    );
    const contractSourcePhysicalObjectCount = requireExactNumber(
        input.executionContract.sourcePhysicalObjectCount,
        8,
        'executionContract.sourcePhysicalObjectCount',
    );
    const contractProofPhysicalObjectCount = requireExactNumber(
        input.executionContract.proofPhysicalObjectCount,
        1,
        'executionContract.proofPhysicalObjectCount',
    );
    if (
        result.backend !== contractBackend ||
        result.custodyModel !== contractCustodyModel ||
        result.custodySchemaIdentifier !== contractCustodySchemaIdentifier ||
        result.custodySchemaVersion !== contractCustodySchemaVersion ||
        result.sourcePhysicalObjectCount !==
            BigInt(contractSourcePhysicalObjectCount) ||
        result.proofPhysicalObjectCount !==
            BigInt(contractProofPhysicalObjectCount)
    ) {
        throw new Error(
            `The raw ${result.backend} result does not match its scheduled ${contractBackend} execution contract.`,
        );
    }
    const memory = extractProofBackendBakeoffOperationMemory({
        guardJsonLines: input.guardJsonLines,
        operationFinishedAtUnixMilliseconds:
            result.operationFinishedAtUnixMilliseconds,
        operationStartedAtUnixMilliseconds:
            result.operationStartedAtUnixMilliseconds,
    });
    return {
        baselineProcessTreeResidentMemoryByteLength:
            memory.baselineProcessTreeResidentMemoryByteLength,
        peakProcessTreeResidentMemoryByteLength:
            memory.peakProcessTreeResidentMemoryByteLength,
        result,
    };
};

const medianOfThree = (first: bigint, second: bigint, third: bigint): bigint =>
    [first, second, third].sort((left, right) =>
        left < right ? -1 : left > right ? 1 : 0,
    )[1];

export const aggregateProofBackendBakeoffArm = (
    samples: readonly ValidatedProofBackendBakeoffSample[],
): ProofBackendBakeoffArmResult => {
    if (
        samples.length !== 3 ||
        samples.some(
            (sample, sampleIndex) =>
                sample.result.sampleOrdinal !== sampleIndex + 1,
        )
    ) {
        throw new Error(
            'A bakeoff arm requires exactly sample ordinals one through three in order.',
        );
    }
    const first = samples[0];
    const second = samples[1];
    const third = samples[2];
    if (first === undefined || second === undefined || third === undefined) {
        throw new Error('A bakeoff arm requires exactly three samples.');
    }
    if (
        samples.some(
            (sample) =>
                sample.result.backend !== first.result.backend ||
                sample.result.custodyModel !== first.result.custodyModel ||
                sample.result.custodySchemaIdentifier !==
                    first.result.custodySchemaIdentifier ||
                sample.result.custodySchemaVersion !==
                    first.result.custodySchemaVersion ||
                sample.result.frozenInputIdentityShake256Hex !==
                    first.result.frozenInputIdentityShake256Hex,
        )
    ) {
        throw new Error(
            'A bakeoff arm must use one backend, one custody model, and one frozen input identity.',
        );
    }
    if (
        samples.some(
            (sample) =>
                sample.result.proofShake256Hex !==
                    first.result.proofShake256Hex ||
                sample.result.canonicalProofByteLength !==
                    first.result.canonicalProofByteLength,
        )
    ) {
        throw new Error(
            'A bakeoff arm produced nondeterministic canonical proof bytes.',
        );
    }
    if (
        samples.some(
            (sample) =>
                sample.result.externalReadByteLength !==
                    first.result.externalReadByteLength ||
                sample.result.externalWrittenByteLength !==
                    first.result.externalWrittenByteLength ||
                sample.result.externalIoByteLength !==
                    first.result.externalIoByteLength,
        )
    ) {
        throw new Error(
            'A bakeoff arm produced nondeterministic external I/O.',
        );
    }
    if (
        samples.some(
            (sample) =>
                sample.result.sourcePhysicalObjectCount !==
                    first.result.sourcePhysicalObjectCount ||
                sample.result.proofPhysicalObjectCount !==
                    first.result.proofPhysicalObjectCount ||
                sample.result.externalCommittedTransactionCount !==
                    first.result.externalCommittedTransactionCount,
        )
    ) {
        throw new Error(
            'A bakeoff arm produced nondeterministic physical-object or transaction counts.',
        );
    }

    return {
        backend: first.result.backend,
        canonicalProofByteLength: first.result.canonicalProofByteLength,
        custodyCleanupCompleted: true,
        custodyModel: first.result.custodyModel,
        custodySchemaIdentifier: first.result.custodySchemaIdentifier,
        custodySchemaVersion: first.result.custodySchemaVersion,
        externalCommittedTransactionCount:
            first.result.externalCommittedTransactionCount,
        externalIoByteLength: first.result.externalIoByteLength,
        externalReadByteLength: first.result.externalReadByteLength,
        externalWrittenByteLength: first.result.externalWrittenByteLength,
        frozenInputIdentityShake256Hex:
            first.result.frozenInputIdentityShake256Hex,
        maximumBaselineProcessTreeResidentMemoryByteLength: maximum(
            samples.map(
                (sample) => sample.baselineProcessTreeResidentMemoryByteLength,
            ),
        ),
        maximumPeakProcessTreeResidentMemoryByteLength: maximum(
            samples.map(
                (sample) => sample.peakProcessTreeResidentMemoryByteLength,
            ),
        ),
        medianElapsedNanoseconds: medianOfThree(
            first.result.elapsedNanoseconds,
            second.result.elapsedNanoseconds,
            third.result.elapsedNanoseconds,
        ),
        proofPhysicalObjectCount: first.result.proofPhysicalObjectCount,
        proofShake256Hex: first.result.proofShake256Hex,
        sampleCount: 3,
        sourcePhysicalObjectCount: first.result.sourcePhysicalObjectCount,
    };
};

type ExactFactorTwoComparison = 'left-wins' | 'neutral' | 'right-wins';

export const compareLowerIsBetterByExactFactorTwo = (
    left: bigint,
    right: bigint,
): ExactFactorTwoComparison => {
    requireUnsigned64(left, 'left metric');
    requireUnsigned64(right, 'right metric');
    if (left === 0n && right === 0n) {
        return 'neutral';
    }
    if (left === 0n) {
        return 'left-wins';
    }
    if (right === 0n) {
        return 'right-wins';
    }
    if (left * 2n <= right) {
        return 'left-wins';
    }
    if (right * 2n <= left) {
        return 'right-wins';
    }
    return 'neutral';
};

const validateArmResult = (result: ProofBackendBakeoffArmResult): void => {
    requireBackend(result.backend);
    requireCustodyModel(result.custodyModel);
    requireExactString(
        result.custodySchemaIdentifier,
        proofBackendBakeoffCustodySchemaIdentifier,
        'custodySchemaIdentifier',
    );
    requireExactNumber(
        result.custodySchemaVersion,
        proofBackendBakeoffCustodySchemaVersion,
        'custodySchemaVersion',
    );
    if (result.custodyCleanupCompleted !== true) {
        throw new Error('custodyCleanupCompleted must be true.');
    }
    requireHash512Hex(
        result.frozenInputIdentityShake256Hex,
        'frozenInputIdentityShake256Hex',
    );
    requireHash512Hex(result.proofShake256Hex, 'proofShake256Hex');
    for (const [fieldName, value] of [
        ['canonicalProofByteLength', result.canonicalProofByteLength],
        [
            'externalCommittedTransactionCount',
            result.externalCommittedTransactionCount,
        ],
        ['externalIoByteLength', result.externalIoByteLength],
        ['externalReadByteLength', result.externalReadByteLength],
        ['externalWrittenByteLength', result.externalWrittenByteLength],
        ['proofPhysicalObjectCount', result.proofPhysicalObjectCount],
        ['sourcePhysicalObjectCount', result.sourcePhysicalObjectCount],
        [
            'maximumBaselineProcessTreeResidentMemoryByteLength',
            result.maximumBaselineProcessTreeResidentMemoryByteLength,
        ],
        [
            'maximumPeakProcessTreeResidentMemoryByteLength',
            result.maximumPeakProcessTreeResidentMemoryByteLength,
        ],
        ['medianElapsedNanoseconds', result.medianElapsedNanoseconds],
    ] as const) {
        requireUnsigned64(value, fieldName);
    }
    if (
        checkedAddUnsigned64(
            result.externalReadByteLength,
            result.externalWrittenByteLength,
            'externalIoByteLength',
        ) !== result.externalIoByteLength
    ) {
        throw new Error('The arm result external I/O total is inconsistent.');
    }
    if (
        result.externalReadByteLength === 0n ||
        result.externalWrittenByteLength === 0n ||
        result.externalCommittedTransactionCount === 0n
    ) {
        throw new Error(
            'A selectable arm must report positive external reads, writes, and committed transactions.',
        );
    }
    if (
        result.sampleCount !== 3 ||
        result.canonicalProofByteLength === 0n ||
        result.medianElapsedNanoseconds === 0n ||
        result.sourcePhysicalObjectCount !== 8n ||
        result.proofPhysicalObjectCount !== 1n
    ) {
        throw new Error('The arm result is incomplete.');
    }
};

export const selectProofBackendBakeoffWinner = (
    packedDeepFri: ProofBackendBakeoffArmResult,
    sumcheckClass: ProofBackendBakeoffArmResult,
): ProofBackendBakeoffDecision => {
    validateArmResult(packedDeepFri);
    validateArmResult(sumcheckClass);
    if (
        packedDeepFri.backend !== 'packed-deep-fri' ||
        sumcheckClass.backend !== 'sumcheck-class' ||
        packedDeepFri.frozenInputIdentityShake256Hex !==
            sumcheckClass.frozenInputIdentityShake256Hex
    ) {
        throw new Error(
            'The bakeoff must compare both ordered arms on one frozen input.',
        );
    }
    if (
        packedDeepFri.custodyModel !== sumcheckClass.custodyModel ||
        packedDeepFri.custodySchemaIdentifier !==
            sumcheckClass.custodySchemaIdentifier ||
        packedDeepFri.custodySchemaVersion !==
            sumcheckClass.custodySchemaVersion ||
        packedDeepFri.sourcePhysicalObjectCount !==
            sumcheckClass.sourcePhysicalObjectCount
    ) {
        throw new Error(
            'The bakeoff arms use mismatched custody models, schemas, or replay-source object counts.',
        );
    }

    const metricValues = {
        'elapsed-time': [
            packedDeepFri.medianElapsedNanoseconds,
            sumcheckClass.medianElapsedNanoseconds,
        ],
        'external-io': [
            packedDeepFri.externalIoByteLength,
            sumcheckClass.externalIoByteLength,
        ],
        'external-transactions': [
            packedDeepFri.externalCommittedTransactionCount,
            sumcheckClass.externalCommittedTransactionCount,
        ],
        'peak-resident-memory': [
            packedDeepFri.maximumPeakProcessTreeResidentMemoryByteLength,
            sumcheckClass.maximumPeakProcessTreeResidentMemoryByteLength,
        ],
        'proof-bytes': [
            packedDeepFri.canonicalProofByteLength,
            sumcheckClass.canonicalProofByteLength,
        ],
    } as const satisfies Record<
        ProofBackendBakeoffMetricName,
        readonly [bigint, bigint]
    >;
    const metricWinners = Object.fromEntries(
        Object.entries(metricValues).map(([metricName, values]) => {
            const comparison = compareLowerIsBetterByExactFactorTwo(
                values[0],
                values[1],
            );
            return [
                metricName,
                comparison === 'left-wins'
                    ? 'packed-deep-fri'
                    : comparison === 'right-wins'
                      ? 'sumcheck-class'
                      : 'neutral',
            ];
        }),
    ) as Record<ProofBackendBakeoffMetricName, ProofBackendBakeoffMetricWinner>;
    const packedDeepFriWinCount = Object.values(metricWinners).filter(
        (winner) => winner === 'packed-deep-fri',
    ).length;
    const sumcheckClassWinCount = Object.values(metricWinners).filter(
        (winner) => winner === 'sumcheck-class',
    ).length;
    const requiredEligibleMetricWinCount = 3;
    const selectedBackend =
        packedDeepFriWinCount >= requiredEligibleMetricWinCount
            ? 'packed-deep-fri'
            : sumcheckClassWinCount >= requiredEligibleMetricWinCount
              ? 'sumcheck-class'
              : undefined;

    return {
        custodyModel: packedDeepFri.custodyModel,
        custodySchemaIdentifier: packedDeepFri.custodySchemaIdentifier,
        custodySchemaVersion: packedDeepFri.custodySchemaVersion,
        eligibleMetrics: proofBackendBakeoffEligibleMetrics,
        excludedMetrics: proofBackendBakeoffExcludedMetrics,
        metricWinners,
        outcome: selectedBackend === undefined ? 'ambiguous' : 'selected',
        packedDeepFriWinCount,
        ...(selectedBackend === undefined ? {} : { selectedBackend }),
        sumcheckClassWinCount,
    };
};

export const evaluateProofBackendBakeoff = (
    samples: readonly ValidatedProofBackendBakeoffSample[],
): Readonly<{
    decision: ProofBackendBakeoffDecision;
    packedDeepFri: ProofBackendBakeoffArmResult;
    sumcheckClass: ProofBackendBakeoffArmResult;
}> => {
    if (samples.length !== proofBackendBakeoffSchedule.length) {
        throw new Error(
            'The bakeoff requires exactly six samples; no additional sample is permitted.',
        );
    }
    for (const [
        scheduleIndex,
        expected,
    ] of proofBackendBakeoffSchedule.entries()) {
        const actual = samples[scheduleIndex]?.result;
        if (
            actual?.backend !== expected.backend ||
            actual.sampleOrdinal !== expected.sampleOrdinal
        ) {
            throw new Error(
                `Bakeoff sample ${scheduleIndex + 1} violates the fixed interleaved schedule.`,
            );
        }
    }
    const frozenInputIdentityShake256Hex =
        samples[0]?.result.frozenInputIdentityShake256Hex;
    if (
        frozenInputIdentityShake256Hex === undefined ||
        samples.some(
            (sample) =>
                sample.result.frozenInputIdentityShake256Hex !==
                frozenInputIdentityShake256Hex,
        )
    ) {
        throw new Error('Every bakeoff sample must use one frozen input.');
    }
    const packedDeepFri = aggregateProofBackendBakeoffArm(
        samples.filter((sample) => sample.result.backend === 'packed-deep-fri'),
    );
    const sumcheckClass = aggregateProofBackendBakeoffArm(
        samples.filter((sample) => sample.result.backend === 'sumcheck-class'),
    );
    return {
        decision: selectProofBackendBakeoffWinner(packedDeepFri, sumcheckClass),
        packedDeepFri,
        sumcheckClass,
    };
};
