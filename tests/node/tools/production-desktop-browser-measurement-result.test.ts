import { describe, expect, it, vi } from 'vitest';

import {
    formatProductionDesktopBrowserMeasurementResult,
    persistProductionDesktopBrowserMeasurementResult,
} from '#packages/protocol/tests/support/production-desktop-browser-measurement-result';

type TestMeasurement = Readonly<{
    caseIdentifier: string;
    measuredByteLength: number;
}>;

const caseIdentifier = 'selected-browser-operation';
const commandIdentifier = 'vitest-browser-selected-browser-operation';
const validMeasurement = (): TestMeasurement =>
    Object.freeze({ caseIdentifier, measuredByteLength: 37 });

const validateMeasurement = (
    value: unknown,
    selectedCaseIdentifier: string,
): TestMeasurement => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error('The test measurement must be an object.');
    }
    const record = value as Record<string, unknown>;
    if (
        record.caseIdentifier !== selectedCaseIdentifier ||
        !Number.isSafeInteger(record.measuredByteLength) ||
        Number(record.measuredByteLength) < 0
    ) {
        throw new Error('The test measurement is invalid.');
    }
    return Object.freeze({
        caseIdentifier: selectedCaseIdentifier,
        measuredByteLength: Number(record.measuredByteLength),
    });
};

const outputLine = (measurement: unknown): string =>
    `2026-07-18T10:00:00.000Z +0000000001ms [${commandIdentifier}] [stdout] ${formatProductionDesktopBrowserMeasurementResult(measurement)}`;

describe('Production desktop-browser measurement result persistence', () => {
    it('refuses unrepresentable results and malformed selection identifiers', async () => {
        expect(() =>
            formatProductionDesktopBrowserMeasurementResult(undefined),
        ).toThrow(/must be JSON-serializable/u);
        const commonInput = {
            caseIdentifier,
            commandIdentifier,
            outputLogText: outputLine(validMeasurement()),
            validateMeasurement,
            writeMeasurementJson: vi.fn(() => Promise.resolve()),
        };
        await expect(
            persistProductionDesktopBrowserMeasurementResult({
                ...commonInput,
                caseIdentifier: 'Selected browser operation',
            }),
        ).rejects.toThrow(/case identifier must be lowercase kebab-case/u);
        await expect(
            persistProductionDesktopBrowserMeasurementResult({
                ...commonInput,
                commandIdentifier: '../selected-command',
            }),
        ).rejects.toThrow(/command identifier must be lowercase kebab-case/u);
        expect(commonInput.writeMeasurementJson).not.toHaveBeenCalled();
    });

    it('validates and writes the selected command result without rewriting its JSON', async () => {
        const measurement = validMeasurement();
        const measurementJson = JSON.stringify(measurement);
        const writeMeasurementJson = vi.fn<(value: string) => Promise<void>>(
            () => Promise.resolve(),
        );

        await expect(
            persistProductionDesktopBrowserMeasurementResult({
                caseIdentifier,
                commandIdentifier,
                outputLogText: [
                    outputLine(measurement),
                    `2026-07-18T10:00:00.001Z +0000000002ms [another-command] [stdout] ${formatProductionDesktopBrowserMeasurementResult(
                        {
                            caseIdentifier: 'another-case',
                            measuredByteLength: 99,
                        },
                    )}`,
                ].join('\n'),
                validateMeasurement,
                writeMeasurementJson,
            }),
        ).resolves.toEqual({ measurement, measurementJson });
        expect(writeMeasurementJson).toHaveBeenCalledExactlyOnceWith(
            measurementJson,
        );
    });

    it('refuses missing and duplicate selected-command results', async () => {
        const commonInput = {
            caseIdentifier,
            commandIdentifier,
            validateMeasurement,
            writeMeasurementJson: vi.fn(() => Promise.resolve()),
        };
        await expect(
            persistProductionDesktopBrowserMeasurementResult({
                ...commonInput,
                outputLogText: '',
            }),
        ).rejects.toThrow(/emitted no structured result/u);
        const line = outputLine(validMeasurement());
        await expect(
            persistProductionDesktopBrowserMeasurementResult({
                ...commonInput,
                outputLogText: `${line}\n${line}`,
            }),
        ).rejects.toThrow(/duplicate structured results/u);
        expect(commonInput.writeMeasurementJson).not.toHaveBeenCalled();
    });

    it('refuses malformed, mismatched, and noncanonical result data', async () => {
        const writeMeasurementJson = vi.fn(() => Promise.resolve());
        const commonInput = {
            caseIdentifier,
            commandIdentifier,
            validateMeasurement,
            writeMeasurementJson,
        };
        await expect(
            persistProductionDesktopBrowserMeasurementResult({
                ...commonInput,
                outputLogText: `2026-07-18T10:00:00.000Z +0000000001ms [${commandIdentifier}] [stdout] sealed-lattice-production-desktop-browser-measurement-result:{broken`,
            }),
        ).rejects.toThrow(/malformed result JSON/u);
        await expect(
            persistProductionDesktopBrowserMeasurementResult({
                ...commonInput,
                outputLogText: outputLine({
                    caseIdentifier: 'different-case',
                    measuredByteLength: 37,
                }),
            }),
        ).rejects.toThrow(/mismatched result case identifier/u);
        await expect(
            persistProductionDesktopBrowserMeasurementResult({
                ...commonInput,
                outputLogText: outputLine({
                    ...validMeasurement(),
                    unexpectedField: true,
                }),
            }),
        ).rejects.toThrow(/noncanonical or unexpected result data/u);
        expect(writeMeasurementJson).not.toHaveBeenCalled();
    });

    it('propagates write-once persistence failures', async () => {
        const persistenceFailure = new Error(
            'The measurement artifact already exists.',
        );
        await expect(
            persistProductionDesktopBrowserMeasurementResult({
                caseIdentifier,
                commandIdentifier,
                outputLogText: outputLine(validMeasurement()),
                validateMeasurement,
                writeMeasurementJson: () => Promise.reject(persistenceFailure),
            }),
        ).rejects.toBe(persistenceFailure);
    });
});
