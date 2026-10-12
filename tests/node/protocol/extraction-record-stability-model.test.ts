import { describe, expect, it } from 'vitest';

import {
    compareCopyAndReadOnlyFeedback,
    discardedQuantumTagRecord,
    simulateReadOnlyExtractionRecord,
} from '#tests/extraction-record-stability-model.js';

describe('retained extraction-record stability', () => {
    it('shows that discarding a record of a coherent tag can change observable output without a query', () => {
        const value = discardedQuantumTagRecord();
        expect(value.initialDensityNumerators).toEqual([1n, 1n, 1n, 1n]);
        expect(value.copiedDensityNumerators).toEqual([1n, 0n, 0n, 1n]);
        // Measuring the tag in the plus/minus basis has plus probability
        // sum(entries)/(2 * densityDenominator): one before, one half after.
        expect(
            value.initialDensityNumerators.reduce(
                (sum, entry) => sum + entry,
                0n,
            ),
        ).toBe(2n * value.densityDenominator);
        expect(
            value.copiedDensityNumerators.reduce(
                (sum, entry) => sum + entry,
                0n,
            ),
        ).toBe(value.densityDenominator);
    });
    it('bounds leakage under every bounded feedback schedule with exact rational amplitudes', () => {
        for (let queries = 0; queries <= 8; queries++)
            for (let feedback = 0; feedback < 2 ** queries; feedback++)
                for (const record of [0, 1]) {
                    const value = simulateReadOnlyExtractionRecord(
                        queries,
                        feedback,
                        record,
                    );
                    expect(
                        value.mismatchNumerator *
                            value.perQueryLeakageSquaredDenominator,
                    ).toBeLessThanOrEqual(
                        BigInt(queries) ** 2n *
                            value.perQueryLeakageSquaredNumerator *
                            value.probabilityDenominator,
                    );
                }
    });

    it('distinguishes preserving an existing record from postponing its creation', () => {
        const value = compareCopyAndReadOnlyFeedback();
        expect(value.copyThenFeedback).toBe(7);
        expect(value.feedbackThenCopy).toBe(6);
        expect(value.feedbackPreservesEquality).toEqual(
            Array<boolean>(8).fill(true),
        );
        expect(value.overwrittenRecordPreservesEquality).toBe(false);
    });

    it('needs no query bound to preserve an untouched fresh record', () => {
        for (const record of [0, 1])
            expect(
                simulateReadOnlyExtractionRecord(0, 0, record)
                    .mismatchNumerator,
            ).toBe(0n);
        for (const input of [
            [-1, 0, 0],
            [9, 0, 0],
            [1, 2, 0],
            [1, 0, 2],
            [0.5, 0, 0],
        ])
            expect(() =>
                simulateReadOnlyExtractionRecord(input[0], input[1], input[2]),
            ).toThrow(RangeError);
    });
});
