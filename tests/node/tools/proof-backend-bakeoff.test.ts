import { describe, expect, it } from 'vitest';

import {
    aggregateProofBackendBakeoffArm,
    auditHistoricalProofBackendBakeoffResult,
    checkedAddUnsigned64,
    compareLowerIsBetterByExactFactorTwo,
    evaluateProofBackendBakeoff,
    extractProofBackendBakeoffOperationMemory,
    parseCanonicalUnsigned64Decimal,
    proofBackendBakeoffCustodyModel,
    proofBackendBakeoffCustodySchemaIdentifier,
    proofBackendBakeoffCustodySchemaVersion,
    proofBackendBakeoffEligibleMetrics,
    proofBackendBakeoffExecutionContracts,
    proofBackendBakeoffExcludedMetrics,
    proofBackendBakeoffSchedule,
    selectProofBackendBakeoffWinner,
    validateProofBackendBakeoffResult,
    validateProofBackendBakeoffSample,
    type ProofBackendName,
} from '#tools/ci/proof-backend-bakeoff';

const maximumUnsigned64Decimal = '18446744073709551615';
const frozenInputIdentityShake256Hex = '12'.repeat(64);

const historicalSampleResult = (
    overrides: Readonly<Record<string, unknown>> = {},
): Readonly<Record<string, unknown>> => ({
    backend: 'packed-deep-fri',
    canonicalProofByteLengthDecimal: '100',
    elapsedNanosecondsDecimal: '200',
    externalCommittedTransactionCountDecimal: '5',
    externalReadByteLengthDecimal: '30',
    externalWrittenByteLengthDecimal: '40',
    formatVersion: 1,
    frozenInputIdentityShake256Hex,
    operationFinishedAtUnixMilliseconds: 1_100,
    operationStartedAtUnixMilliseconds: 1_000,
    proofShake256Hex: '34'.repeat(64),
    sampleOrdinal: 1,
    ...overrides,
});

const sampleResult = (
    overrides: Readonly<Record<string, unknown>> = {},
): Readonly<Record<string, unknown>> => ({
    backend: 'packed-deep-fri',
    canonicalProofByteLengthDecimal: '100',
    custodyCleanupCompleted: true,
    custodyModel: proofBackendBakeoffCustodyModel,
    custodySchemaIdentifier: proofBackendBakeoffCustodySchemaIdentifier,
    custodySchemaVersion: proofBackendBakeoffCustodySchemaVersion,
    elapsedNanosecondsDecimal: '200',
    externalCommittedTransactionCountDecimal: '5',
    externalReadByteLengthDecimal: '30',
    externalWrittenByteLengthDecimal: '40',
    formatVersion: 2,
    frozenInputIdentityShake256Hex,
    operationFinishedAtUnixMilliseconds: 1_100,
    operationStartedAtUnixMilliseconds: 1_000,
    proofPhysicalObjectCountDecimal: '1',
    proofShake256Hex: '34'.repeat(64),
    sampleOrdinal: 1,
    sourcePhysicalObjectCountDecimal: '8',
    ...overrides,
});

const guardJsonLines = (
    overrides: Readonly<{
        guardIntervalMilliseconds?: number;
        includeBaseline?: boolean;
        includeInWindow?: boolean;
        includeTerminal?: boolean;
        baselineResidentMemoryByteLength?: number;
        peakResidentMemoryByteLength?: number;
        sampleError?: string;
    }> = {},
): string => {
    const records: Array<Record<string, unknown>> = [
        {
            aggregateProcessTreeMemoryLimit: true,
            eventType: 'guard-started',
            recordedAtUnixMilliseconds: 900,
            resourceSampleIntervalMilliseconds:
                overrides.guardIntervalMilliseconds ?? 100,
        },
        {
            eventType: 'child-started',
            recordedAtUnixMilliseconds: 950,
        },
    ];
    if (overrides.includeBaseline !== false) {
        records.push({
            confirmedMemoryLimitViolation: false,
            eventType: 'resource-sample',
            processTreeResidentMemoryBytes:
                overrides.baselineResidentMemoryByteLength ?? 50,
            recordedAtUnixMilliseconds: 999,
            sampleError: null,
        });
    }
    if (overrides.includeInWindow !== false) {
        records.push(
            {
                confirmedMemoryLimitViolation: false,
                eventType: 'resource-sample',
                processTreeResidentMemoryBytes:
                    overrides.peakResidentMemoryByteLength ?? 70,
                recordedAtUnixMilliseconds: 1_000,
                sampleError: null,
            },
            {
                confirmedMemoryLimitViolation: false,
                eventType: 'resource-sample',
                processTreeResidentMemoryBytes:
                    overrides.peakResidentMemoryByteLength ?? 80,
                recordedAtUnixMilliseconds: 1_050,
                sampleError: overrides.sampleError ?? null,
            },
            {
                confirmedMemoryLimitViolation: false,
                eventType: 'resource-sample',
                processTreeResidentMemoryBytes:
                    overrides.peakResidentMemoryByteLength ?? 90,
                recordedAtUnixMilliseconds: 1_100,
                sampleError: null,
            },
        );
    }
    records.push({
        confirmedMemoryLimitViolation: false,
        eventType: 'resource-sample',
        processTreeResidentMemoryBytes: 500,
        recordedAtUnixMilliseconds: 1_101,
        sampleError: null,
    });
    if (overrides.includeTerminal !== false) {
        records.push({
            eventType: 'child-exited',
            exitCode: 0,
            memoryEvidence: 'completed',
            recordedAtUnixMilliseconds: 1_200,
            terminationClassification: 'completed',
        });
    }
    return records
        .map((record, recordIndex) =>
            JSON.stringify({
                elapsedMilliseconds:
                    Number(record.recordedAtUnixMilliseconds) - 900,
                ...record,
                sequence: recordIndex,
            }),
        )
        .join('\n');
};

const mutateGuardJsonLines = (
    serialized: string,
    mutation: (records: Array<Record<string, unknown>>) => void,
): string => {
    const records = serialized
        .split('\n')
        .map((line) => JSON.parse(line) as Record<string, unknown>);
    mutation(records);
    return records.map((record) => JSON.stringify(record)).join('\n');
};

const requiredGuardRecord = (
    records: readonly Record<string, unknown>[],
    recordIndex: number,
): Record<string, unknown> => {
    const record = records[recordIndex];
    if (record === undefined) {
        throw new Error(`Missing guard record ${recordIndex}.`);
    }
    return record;
};

const validatedSample = (
    backend: ProofBackendName,
    sampleOrdinal: 1 | 2 | 3,
    overrides: Readonly<{
        baseline?: bigint;
        elapsed?: bigint;
        io?: bigint;
        peak?: bigint;
        proofByteLength?: bigint;
        proofDigestByte?: string;
        transactions?: bigint;
    }> = {},
): ReturnType<typeof validateProofBackendBakeoffSample> => {
    const externalIoByteLength = overrides.io ?? 30n;
    if (externalIoByteLength < 2n) {
        throw new Error(
            'Test samples require at least two external I/O bytes.',
        );
    }
    return validateProofBackendBakeoffSample({
        executionContract: proofBackendBakeoffExecutionContracts[backend],
        guardJsonLines: guardJsonLines({
            baselineResidentMemoryByteLength: Number(overrides.baseline ?? 40n),
            peakResidentMemoryByteLength: Number(overrides.peak ?? 100n),
        }),
        result: sampleResult({
            backend,
            canonicalProofByteLengthDecimal: (
                overrides.proofByteLength ?? 80n
            ).toString(),
            elapsedNanosecondsDecimal: (overrides.elapsed ?? 120n).toString(),
            externalCommittedTransactionCountDecimal: (
                overrides.transactions ?? 4n
            ).toString(),
            externalReadByteLengthDecimal: (
                externalIoByteLength - 1n
            ).toString(),
            externalWrittenByteLengthDecimal: '1',
            proofShake256Hex: (overrides.proofDigestByte ?? '56').repeat(64),
            sampleOrdinal,
        }),
    });
};

const armResult = (
    backend: ProofBackendName,
    metrics: Readonly<{
        elapsed: bigint;
        io: bigint;
        peak: bigint;
        proofBytes: bigint;
        transactions: bigint;
    }>,
): ReturnType<typeof aggregateProofBackendBakeoffArm> =>
    aggregateProofBackendBakeoffArm(
        ([1, 2, 3] as const).map((sampleOrdinal) =>
            validatedSample(backend, sampleOrdinal, {
                elapsed: metrics.elapsed,
                io: metrics.io,
                peak: metrics.peak,
                proofByteLength: metrics.proofBytes,
                proofDigestByte: backend === 'packed-deep-fri' ? '67' : '89',
                transactions: metrics.transactions,
            }),
        ),
    );

describe('proof backend bakeoff contracts', () => {
    it('pins canonical decimal u64 syntax, the maximum value, and checked read plus write', () => {
        expect(
            parseCanonicalUnsigned64Decimal(
                maximumUnsigned64Decimal,
                'maximum',
            ),
        ).toBe(18_446_744_073_709_551_615n);
        expect(
            checkedAddUnsigned64(18_446_744_073_709_551_614n, 1n, 'io'),
        ).toBe(18_446_744_073_709_551_615n);
        for (const invalid of [
            '',
            '00',
            '01',
            '+1',
            '-1',
            ' 1',
            '1.0',
            '18446744073709551616',
        ]) {
            expect(() =>
                parseCanonicalUnsigned64Decimal(invalid, 'value'),
            ).toThrow();
        }
        expect(() =>
            checkedAddUnsigned64(18_446_744_073_709_551_615n, 1n, 'io'),
        ).toThrow('exceeds u64');
    });

    it('keeps historical format version one audit-only and ineligible for selection', () => {
        const result = auditHistoricalProofBackendBakeoffResult(
            historicalSampleResult(),
        );
        expect(result).toMatchObject({
            backend: 'packed-deep-fri',
            externalIoByteLength: 70n,
            formatVersion: 1,
            sampleOrdinal: 1,
        });
        expect(() =>
            validateProofBackendBakeoffResult(historicalSampleResult()),
        ).toThrow(/historical audit evidence.*ineligible/u);
        expect(() =>
            validateProofBackendBakeoffSample({
                executionContract:
                    proofBackendBakeoffExecutionContracts['packed-deep-fri'],
                guardJsonLines: guardJsonLines(),
                result: historicalSampleResult(),
            }),
        ).toThrow(/historical audit evidence.*ineligible/u);
    });

    it('validates the exact selectable format-version-two custody schema and accepts u64 maxima', () => {
        const result = validateProofBackendBakeoffResult(
            sampleResult({
                canonicalProofByteLengthDecimal: maximumUnsigned64Decimal,
                elapsedNanosecondsDecimal: maximumUnsigned64Decimal,
                externalReadByteLengthDecimal: '18446744073709551614',
                externalWrittenByteLengthDecimal: '1',
            }),
        );

        expect(result).toMatchObject({
            backend: 'packed-deep-fri',
            canonicalProofByteLength: 18_446_744_073_709_551_615n,
            externalIoByteLength: 18_446_744_073_709_551_615n,
            custodyCleanupCompleted: true,
            custodyModel: 'bounded-external-storage-replay',
            custodySchemaIdentifier: 'bounded-external-storage-replay-v1',
            custodySchemaVersion: 1,
            formatVersion: 2,
            proofPhysicalObjectCount: 1n,
            sampleOrdinal: 1,
            sourcePhysicalObjectCount: 8n,
        });
        expect(() =>
            validateProofBackendBakeoffResult(
                sampleResult({ formatVersion: 3 }),
            ),
        ).toThrow('formatVersion');
        expect(() =>
            validateProofBackendBakeoffResult(
                sampleResult({ proofShake256Hex: 'AB'.repeat(64) }),
            ),
        ).toThrow('proofShake256Hex');
        expect(() =>
            validateProofBackendBakeoffResult(
                sampleResult({
                    externalReadByteLengthDecimal: maximumUnsigned64Decimal,
                    externalWrittenByteLengthDecimal: '1',
                }),
            ),
        ).toThrow('externalIoByteLength');
        for (const [fieldName, invalidValue] of [
            ['custodyModel', 'resident-process-memory'],
            ['custodySchemaIdentifier', 'unbounded-memory-v1'],
            ['custodySchemaVersion', 2],
            ['custodyCleanupCompleted', false],
            ['sourcePhysicalObjectCountDecimal', '7'],
            ['proofPhysicalObjectCountDecimal', '2'],
            ['externalReadByteLengthDecimal', '0'],
            ['externalWrittenByteLengthDecimal', '0'],
            ['externalCommittedTransactionCountDecimal', '0'],
        ] as const) {
            expect(() =>
                validateProofBackendBakeoffResult(
                    sampleResult({ [fieldName]: invalidValue }),
                ),
            ).toThrow(fieldName);
        }
    });

    it('extracts the absolute RSS peak from the inclusive operation window', () => {
        const memory = extractProofBackendBakeoffOperationMemory({
            guardJsonLines: guardJsonLines(),
            operationFinishedAtUnixMilliseconds: 1_100n,
            operationStartedAtUnixMilliseconds: 1_000n,
        });

        expect(memory).toEqual({
            baselineProcessTreeResidentMemoryByteLength: 50n,
            inWindowSampleCount: 3,
            peakProcessTreeResidentMemoryByteLength: 90n,
            resourceSampleIntervalMilliseconds: 100n,
        });
        expect(
            validateProofBackendBakeoffSample({
                executionContract:
                    proofBackendBakeoffExecutionContracts['packed-deep-fri'],
                guardJsonLines: guardJsonLines(),
                result: sampleResult(),
            }).peakProcessTreeResidentMemoryByteLength,
        ).toBe(90n);
    });

    it('binds every raw result to its independently selected arm custody contract', () => {
        expect(
            validateProofBackendBakeoffSample({
                executionContract:
                    proofBackendBakeoffExecutionContracts['packed-deep-fri'],
                guardJsonLines: guardJsonLines(),
                result: sampleResult(),
            }).result.custodyModel,
        ).toBe('bounded-external-storage-replay');
        expect(() =>
            validateProofBackendBakeoffSample({
                executionContract:
                    proofBackendBakeoffExecutionContracts['sumcheck-class'],
                guardJsonLines: guardJsonLines(),
                result: sampleResult(),
            }),
        ).toThrow(
            /does not match its scheduled sumcheck-class execution contract/u,
        );
        expect(
            validateProofBackendBakeoffSample({
                executionContract:
                    proofBackendBakeoffExecutionContracts['packed-deep-fri'],
                guardJsonLines: guardJsonLines(),
                result: sampleResult(),
            }).result,
        ).toMatchObject({
            proofPhysicalObjectCount: 1n,
            sourcePhysicalObjectCount: 8n,
        });
    });

    it('accepts a 500 millisecond monotonic sample gap and refuses 501 milliseconds', () => {
        const withGap = (gapMilliseconds: number): string =>
            mutateGuardJsonLines(guardJsonLines(), (records) => {
                requiredGuardRecord(records, 4).elapsedMilliseconds =
                    100 + gapMilliseconds;
                requiredGuardRecord(records, 5).elapsedMilliseconds =
                    200 + gapMilliseconds;
                requiredGuardRecord(records, 6).elapsedMilliseconds =
                    201 + gapMilliseconds;
                requiredGuardRecord(records, 7).elapsedMilliseconds =
                    300 + gapMilliseconds;
            });

        expect(
            extractProofBackendBakeoffOperationMemory({
                guardJsonLines: withGap(500),
                operationFinishedAtUnixMilliseconds: 1_100n,
                operationStartedAtUnixMilliseconds: 1_000n,
            }).inWindowSampleCount,
        ).toBe(3);
        expect(() =>
            extractProofBackendBakeoffOperationMemory({
                guardJsonLines: withGap(501),
                operationFinishedAtUnixMilliseconds: 1_100n,
                operationStartedAtUnixMilliseconds: 1_000n,
            }),
        ).toThrow('gap greater than 500 milliseconds');
    });

    it('rejects omitted sequence numbers and a missing lifecycle record', () => {
        const omittedSequenceNumber = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                for (
                    let recordIndex = 4;
                    recordIndex < records.length;
                    recordIndex += 1
                ) {
                    requiredGuardRecord(records, recordIndex).sequence =
                        recordIndex + 1;
                }
            },
        );
        expect(() =>
            extractProofBackendBakeoffOperationMemory({
                guardJsonLines: omittedSequenceNumber,
                operationFinishedAtUnixMilliseconds: 1_100n,
                operationStartedAtUnixMilliseconds: 1_000n,
            }),
        ).toThrow('start at zero and remain contiguous');

        const missingChildStarted = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                records.splice(1, 1);
                for (const [recordIndex, record] of records.entries()) {
                    record.sequence = recordIndex;
                }
            },
        );
        expect(() =>
            extractProofBackendBakeoffOperationMemory({
                guardJsonLines: missingChildStarted,
                operationFinishedAtUnixMilliseconds: 1_100n,
                operationStartedAtUnixMilliseconds: 1_000n,
            }),
        ).toThrow('contiguous guard-started, child-started');
    });

    it('rejects a wall-clock reversal that could exclude the true peak', () => {
        const reversedWallTime = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                const truePeak = requiredGuardRecord(records, 4);
                truePeak.processTreeResidentMemoryBytes = 999;
                truePeak.recordedAtUnixMilliseconds = 1_101;
                requiredGuardRecord(records, 5).recordedAtUnixMilliseconds =
                    1_100;
            },
        );

        expect(() =>
            extractProofBackendBakeoffOperationMemory({
                guardJsonLines: reversedWallTime,
                operationFinishedAtUnixMilliseconds: 1_100n,
                operationStartedAtUnixMilliseconds: 1_000n,
            }),
        ).toThrow('wall time must be nondecreasing');
    });

    it('requires the complete operation window to remain inside the guarded child lifetime', () => {
        expect(() =>
            extractProofBackendBakeoffOperationMemory({
                guardJsonLines: guardJsonLines(),
                operationFinishedAtUnixMilliseconds: 1_100n,
                operationStartedAtUnixMilliseconds: 949n,
            }),
        ).toThrow('start inside the guarded child lifecycle');
        expect(() =>
            extractProofBackendBakeoffOperationMemory({
                guardJsonLines: guardJsonLines(),
                operationFinishedAtUnixMilliseconds: 1_201n,
                operationStartedAtUnixMilliseconds: 1_000n,
            }),
        ).toThrow('finish inside the guarded child lifecycle');
    });

    it('requires explicit aggregate, error-free, unconstrained resource evidence', () => {
        const nonAggregateGuard = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                requiredGuardRecord(
                    records,
                    0,
                ).aggregateProcessTreeMemoryLimit = false;
            },
        );
        const missingSampleError = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                delete requiredGuardRecord(records, 4).sampleError;
            },
        );
        const confirmedLimitViolation = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                requiredGuardRecord(records, 4).confirmedMemoryLimitViolation =
                    true;
            },
        );

        for (const invalidLog of [
            nonAggregateGuard,
            missingSampleError,
            confirmedLimitViolation,
        ]) {
            expect(() =>
                extractProofBackendBakeoffOperationMemory({
                    guardJsonLines: invalidLog,
                    operationFinishedAtUnixMilliseconds: 1_100n,
                    operationStartedAtUnixMilliseconds: 1_000n,
                }),
            ).toThrow();
        }
    });

    it('fails closed on missing, erroneous, slow, or incomplete guard telemetry', () => {
        const zeroBaseline = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                requiredGuardRecord(records, 2).processTreeResidentMemoryBytes =
                    0;
            },
        );
        const zeroInWindowSample = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                requiredGuardRecord(records, 4).processTreeResidentMemoryBytes =
                    0;
            },
        );
        const duplicateSequence = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                requiredGuardRecord(records, 4).sequence = requiredGuardRecord(
                    records,
                    3,
                ).sequence;
            },
        );
        const decreasingElapsedTime = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                requiredGuardRecord(records, 4).elapsedMilliseconds = 50;
            },
        );
        const sparseOperationWindow = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                requiredGuardRecord(records, 4).elapsedMilliseconds = 700;
                requiredGuardRecord(records, 5).elapsedMilliseconds = 800;
                requiredGuardRecord(records, 6).elapsedMilliseconds = 801;
                requiredGuardRecord(records, 7).elapsedMilliseconds = 900;
            },
        );
        const staleStartBoundary = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                requiredGuardRecord(records, 0).recordedAtUnixMilliseconds =
                    300;
                requiredGuardRecord(records, 1).recordedAtUnixMilliseconds =
                    400;
                requiredGuardRecord(records, 2).recordedAtUnixMilliseconds =
                    499;
            },
        );
        const missingElapsedTime = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                delete requiredGuardRecord(records, 4).elapsedMilliseconds;
            },
        );
        const missingSequence = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                delete requiredGuardRecord(records, 4).sequence;
            },
        );
        const invalidLogs = [
            guardJsonLines({ includeBaseline: false }),
            guardJsonLines({ includeInWindow: false }),
            guardJsonLines({ guardIntervalMilliseconds: 101 }),
            guardJsonLines({ guardIntervalMilliseconds: 99 }),
            guardJsonLines({ sampleError: 'access denied' }),
            guardJsonLines({ includeTerminal: false }),
            `${guardJsonLines()}\n${JSON.stringify({ eventType: 'guard-error' })}`,
            zeroBaseline,
            zeroInWindowSample,
            duplicateSequence,
            decreasingElapsedTime,
            sparseOperationWindow,
            staleStartBoundary,
            missingElapsedTime,
            missingSequence,
        ];
        for (const invalidLog of invalidLogs) {
            expect(() =>
                extractProofBackendBakeoffOperationMemory({
                    guardJsonLines: invalidLog,
                    operationFinishedAtUnixMilliseconds: 1_100n,
                    operationStartedAtUnixMilliseconds: 1_000n,
                }),
            ).toThrow();
        }
        const missingResidentMemory = guardJsonLines().replace(
            '"processTreeResidentMemoryBytes":70,',
            '',
        );
        expect(() =>
            extractProofBackendBakeoffOperationMemory({
                guardJsonLines: missingResidentMemory,
                operationFinishedAtUnixMilliseconds: 1_100n,
                operationStartedAtUnixMilliseconds: 1_000n,
            }),
        ).toThrow('processTreeResidentMemoryBytes');
        const staleFinishCoverage = mutateGuardJsonLines(
            guardJsonLines(),
            (records) => {
                const childExited = requiredGuardRecord(
                    records,
                    records.length - 1,
                );
                childExited.elapsedMilliseconds = 1_600;
                childExited.recordedAtUnixMilliseconds = 2_500;
            },
        );
        expect(() =>
            extractProofBackendBakeoffOperationMemory({
                guardJsonLines: staleFinishCoverage,
                operationFinishedAtUnixMilliseconds: 2_000n,
                operationStartedAtUnixMilliseconds: 1_000n,
            }),
        ).toThrow('operation finish');
    });

    it('aggregates only raw-validated samples with deterministic proof bytes, external I/O, and transactions', () => {
        const baseSamples = [
            validatedSample('packed-deep-fri', 1),
            validatedSample('packed-deep-fri', 2),
            validatedSample('packed-deep-fri', 3),
        ] as const;
        expect(aggregateProofBackendBakeoffArm(baseSamples).sampleCount).toBe(
            3,
        );

        expect(() =>
            aggregateProofBackendBakeoffArm([
                baseSamples[0],
                validatedSample('packed-deep-fri', 2, {
                    proofDigestByte: '57',
                }),
                baseSamples[2],
            ]),
        ).toThrow('proof bytes');
        expect(() =>
            aggregateProofBackendBakeoffArm([
                baseSamples[0],
                validatedSample('packed-deep-fri', 2, { io: 31n }),
                baseSamples[2],
            ]),
        ).toThrow('external I/O');
        expect(() =>
            aggregateProofBackendBakeoffArm([
                baseSamples[0],
                validatedSample('packed-deep-fri', 2, {
                    transactions: 5n,
                }),
                baseSamples[2],
            ]),
        ).toThrow('transaction');
    });

    it('uses median elapsed time and the maximum absolute peak and baseline', () => {
        const result = aggregateProofBackendBakeoffArm([
            validatedSample('sumcheck-class', 1, {
                baseline: 30n,
                elapsed: 900n,
                peak: 100n,
            }),
            validatedSample('sumcheck-class', 2, {
                baseline: 70n,
                elapsed: 100n,
                peak: 400n,
            }),
            validatedSample('sumcheck-class', 3, {
                baseline: 50n,
                elapsed: 500n,
                peak: 200n,
            }),
        ]);

        expect(result.medianElapsedNanoseconds).toBe(500n);
        expect(result.maximumPeakProcessTreeResidentMemoryByteLength).toBe(
            400n,
        );
        expect(result.maximumBaselineProcessTreeResidentMemoryByteLength).toBe(
            70n,
        );
    });

    it('pins the exact factor-two boundary, immediately-below values, zeros, and near-u64 arithmetic', () => {
        expect(compareLowerIsBetterByExactFactorTwo(5n, 10n)).toBe('left-wins');
        expect(compareLowerIsBetterByExactFactorTwo(5n, 9n)).toBe('neutral');
        expect(compareLowerIsBetterByExactFactorTwo(10n, 5n)).toBe(
            'right-wins',
        );
        expect(compareLowerIsBetterByExactFactorTwo(9n, 5n)).toBe('neutral');
        expect(compareLowerIsBetterByExactFactorTwo(0n, 0n)).toBe('neutral');
        expect(compareLowerIsBetterByExactFactorTwo(0n, 1n)).toBe('left-wins');
        expect(compareLowerIsBetterByExactFactorTwo(1n, 0n)).toBe('right-wins');
        expect(
            compareLowerIsBetterByExactFactorTwo(
                9_223_372_036_854_775_807n,
                18_446_744_073_709_551_615n,
            ),
        ).toBe('left-wins');
        expect(
            compareLowerIsBetterByExactFactorTwo(
                9_223_372_036_854_775_808n,
                18_446_744_073_709_551_615n,
            ),
        ).toBe('neutral');
    });

    it('selects one arm only when it wins at least three of the five fixed metrics', () => {
        expect(proofBackendBakeoffEligibleMetrics).toEqual([
            'proof-bytes',
            'elapsed-time',
            'peak-resident-memory',
            'external-io',
            'external-transactions',
        ]);
        expect(proofBackendBakeoffExcludedMetrics).toEqual([]);
        const packedDeepFri = armResult('packed-deep-fri', {
            elapsed: 10n,
            io: 20n,
            peak: 10n,
            proofBytes: 10n,
            transactions: 20n,
        });
        const sumcheckClass = armResult('sumcheck-class', {
            elapsed: 20n,
            io: 10n,
            peak: 20n,
            proofBytes: 20n,
            transactions: 10n,
        });
        expect(
            selectProofBackendBakeoffWinner(packedDeepFri, sumcheckClass),
        ).toMatchObject({
            custodyModel: 'bounded-external-storage-replay',
            custodySchemaIdentifier: 'bounded-external-storage-replay-v1',
            custodySchemaVersion: 1,
            eligibleMetrics: proofBackendBakeoffEligibleMetrics,
            excludedMetrics: proofBackendBakeoffExcludedMetrics,
            metricWinners: {
                'external-io': 'sumcheck-class',
                'external-transactions': 'sumcheck-class',
            },
            outcome: 'selected',
            packedDeepFriWinCount: 3,
            selectedBackend: 'packed-deep-fri',
            sumcheckClassWinCount: 2,
        });

        expect(
            selectProofBackendBakeoffWinner(
                armResult('packed-deep-fri', {
                    elapsed: 10n,
                    io: 20n,
                    peak: 15n,
                    proofBytes: 10n,
                    transactions: 20n,
                }),
                sumcheckClass,
            ),
        ).toMatchObject({
            outcome: 'ambiguous',
            packedDeepFriWinCount: 2,
            sumcheckClassWinCount: 2,
        });

        expect(
            selectProofBackendBakeoffWinner(
                armResult('packed-deep-fri', {
                    elapsed: 10n,
                    io: 10n,
                    peak: 10n,
                    proofBytes: 10n,
                    transactions: 10n,
                }),
                armResult('sumcheck-class', {
                    elapsed: 20n,
                    io: 20n,
                    peak: 20n,
                    proofBytes: 20n,
                    transactions: 20n,
                }),
            ),
        ).toMatchObject({
            outcome: 'selected',
            packedDeepFriWinCount: 5,
            selectedBackend: 'packed-deep-fri',
            sumcheckClassWinCount: 0,
        });

        expect(
            selectProofBackendBakeoffWinner(
                armResult('packed-deep-fri', {
                    elapsed: 20n,
                    io: 20n,
                    peak: 20n,
                    proofBytes: 15n,
                    transactions: 20n,
                }),
                armResult('sumcheck-class', {
                    elapsed: 10n,
                    io: 10n,
                    peak: 10n,
                    proofBytes: 10n,
                    transactions: 10n,
                }),
            ),
        ).toMatchObject({
            outcome: 'selected',
            packedDeepFriWinCount: 0,
            selectedBackend: 'sumcheck-class',
            sumcheckClassWinCount: 4,
        });
    });

    it('reports an ambiguous result when raw-validated arms split two wins each', () => {
        const ambiguous = selectProofBackendBakeoffWinner(
            armResult('packed-deep-fri', {
                elapsed: 10n,
                io: 20n,
                peak: 15n,
                proofBytes: 10n,
                transactions: 20n,
            }),
            armResult('sumcheck-class', {
                elapsed: 20n,
                io: 10n,
                peak: 20n,
                proofBytes: 20n,
                transactions: 10n,
            }),
        );
        expect(ambiguous).toMatchObject({
            outcome: 'ambiguous',
            packedDeepFriWinCount: 2,
            sumcheckClassWinCount: 2,
        });
    });

    it('fails closed on missing raw custody telemetry', () => {
        for (const missingTelemetryField of [
            'externalReadByteLengthDecimal',
            'externalWrittenByteLengthDecimal',
            'externalCommittedTransactionCountDecimal',
        ]) {
            expect(() =>
                validateProofBackendBakeoffResult(
                    sampleResult({ [missingTelemetryField]: undefined }),
                ),
            ).toThrow(missingTelemetryField);
        }
    });

    it('enforces the fixed six-entry interleaved schedule and permits no seventh sample', () => {
        expect(proofBackendBakeoffSchedule).toEqual([
            { backend: 'packed-deep-fri', sampleOrdinal: 1 },
            { backend: 'sumcheck-class', sampleOrdinal: 1 },
            { backend: 'packed-deep-fri', sampleOrdinal: 2 },
            { backend: 'sumcheck-class', sampleOrdinal: 2 },
            { backend: 'packed-deep-fri', sampleOrdinal: 3 },
            { backend: 'sumcheck-class', sampleOrdinal: 3 },
        ]);
        const samples = proofBackendBakeoffSchedule.map((entry) =>
            validatedSample(entry.backend, entry.sampleOrdinal, {
                proofDigestByte:
                    entry.backend === 'packed-deep-fri' ? '56' : '78',
            }),
        );
        expect(evaluateProofBackendBakeoff(samples).decision.outcome).toBe(
            'ambiguous',
        );
        expect(() =>
            evaluateProofBackendBakeoff([
                samples[1],
                samples[0],
                ...samples.slice(2),
            ]),
        ).toThrow('interleaved schedule');
        expect(() =>
            evaluateProofBackendBakeoff([...samples, samples[0]]),
        ).toThrow('exactly six');
    });
});
