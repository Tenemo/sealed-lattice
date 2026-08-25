import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    preparationFieldWasmMeasurementRegistry,
    resolvePreparationFieldWasmMeasurement,
} from '#tools/ci/preparation-field-wasm-measurement-registry.js';
import { parsePreparationFieldWasmMeasurementWorkerArguments } from '#tools/ci/preparation-field-wasm-measurement-worker.js';
import { parsePreparationFieldWasmMeasurementArguments } from '#tools/ci/run-preparation-field-wasm-measurement.js';

const measurementId = 'reviewed-completion-profile-field-floor-screen';

describe('preparation-field WebAssembly measurement registry', () => {
    it('owns one immutable rounded external-model screen', () => {
        const measurement =
            resolvePreparationFieldWasmMeasurement(measurementId);

        expect(Object.isFrozen(preparationFieldWasmMeasurementRegistry)).toBe(
            true,
        );
        expect(Object.isFrozen(measurement)).toBe(true);
        expect(measurement).toEqual({
            evidenceClassification:
                'rounded external-model scalar WebAssembly operation-floor screen',
            measurementId,
            multiplicationCount: 12_500_000,
            seed: 0xd6e8_feb8_6659_fd93n,
            warmupMultiplicationCount: 100_000,
        });
    });

    it('rejects zero-match identifiers instead of running an empty selection', () => {
        expect(() =>
            resolvePreparationFieldWasmMeasurement('missing-measurement'),
        ).toThrow(/No preparation-field WebAssembly measurement matches/u);
    });
});

describe('preparation-field WebAssembly measurement arguments', () => {
    it('accepts exactly one registered identifier with an optional separator', () => {
        expect(
            parsePreparationFieldWasmMeasurementArguments([measurementId]),
        ).toEqual({ measurementId });
        expect(
            parsePreparationFieldWasmMeasurementArguments([
                '--',
                measurementId,
            ]),
        ).toEqual({ measurementId });
    });

    it.each([
        { arguments_: [] },
        { arguments_: [''] },
        { arguments_: ['--unknown'] },
        { arguments_: ['missing-measurement'] },
        { arguments_: [measurementId, measurementId] },
    ])('rejects an invalid runner selection %#', ({ arguments_ }) => {
        expect(() =>
            parsePreparationFieldWasmMeasurementArguments(arguments_),
        ).toThrow();
    });
});

describe('preparation-field WebAssembly measurement worker arguments', () => {
    it('requires a registered identifier and absolute diagnostic output path', () => {
        const outputFilePath = path.resolve(
            'logs',
            'measurement',
            'result.json',
        );
        expect(
            parsePreparationFieldWasmMeasurementWorkerArguments([
                '--output',
                outputFilePath,
                '--measurement',
                measurementId,
            ]),
        ).toEqual({ measurementId, outputFilePath });
    });

    it.each([
        { arguments_: [] },
        { arguments_: ['--measurement', measurementId] },
        { arguments_: ['--output', path.resolve('result.json')] },
        {
            arguments_: [
                '--measurement',
                measurementId,
                '--output',
                'relative.json',
            ],
        },
        { arguments_: ['--unknown', 'value'] },
        { arguments_: ['--measurement'] },
    ])('rejects malformed worker arguments %#', ({ arguments_ }) => {
        expect(() =>
            parsePreparationFieldWasmMeasurementWorkerArguments(arguments_),
        ).toThrow();
    });
});
