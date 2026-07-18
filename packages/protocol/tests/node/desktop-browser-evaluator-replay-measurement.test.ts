import { describe, expect, it } from 'vitest';

import {
    measureProductionDesktopBrowserEvaluatorReplayCase,
    type DesktopBrowserEvaluatorReplayMeasurement,
} from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement';
import {
    productionDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier,
    requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier,
} from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement-case-identifier';
import { validateDesktopBrowserEvaluatorReplayMeasurement } from '#packages/protocol/tests/support/desktop-browser-evaluator-replay-measurement-worker-protocol';

const validMeasurement = (): DesktopBrowserEvaluatorReplayMeasurement =>
    Object.freeze({
        boundaryBufferTraffic: Object.freeze({
            bufferCount: 6,
            maximumBufferByteLength: 48,
            totalByteLength: 160,
        }),
        canonicalReplayCarrierTraffic: Object.freeze({
            boardIngressByteLength: 48,
            copyByteLength: 48,
        }),
        caseIdentifier: 'selected-evaluator-replay',
        elapsedMilliseconds: 12.5,
        evaluatorKeyStoreTraffic: Object.freeze({
            declaredByteLength: 64,
            distinctReadByteLength: 64,
            readCount: 4,
            rereadByteLength: 0,
            requestedReadByteLength: 64,
            returnedReadByteLength: 64,
        }),
        measurementIdentity: Object.freeze({
            actionContextHash: '11'.repeat(64),
            inputCorpusHash: '22'.repeat(64),
            manifestHash: '33'.repeat(64),
            packagedWasmSha256: '44'.repeat(32),
            runtimeBuildManifestHash: '55'.repeat(64),
            suiteIdentifier: '66'.repeat(64),
        }),
        publicOutputHashes: Object.freeze({
            canonicalReplayCarrierSha512: '77'.repeat(64),
        }),
        schedulerYieldCount: 4,
        wasmMemory: Object.freeze({
            finalByteLength: 196_608,
            growthByteLength: 65_536,
            growthObservationCount: 1,
            initialByteLength: 131_072,
            observationCount: 18,
            peakByteLength: 196_608,
        }),
    });

describe('Desktop-browser evaluator-replay measurement accounting', () => {
    it('accepts mutually consistent exact traffic and memory accounting', () => {
        expect(
            validateDesktopBrowserEvaluatorReplayMeasurement(
                validMeasurement(),
                'selected-evaluator-replay',
            ),
        ).toEqual(validMeasurement());
    });

    it('refuses incomplete store coverage and mismatched carrier traffic', () => {
        const measurement = validMeasurement();
        expect(() =>
            validateDesktopBrowserEvaluatorReplayMeasurement(
                {
                    ...measurement,
                    evaluatorKeyStoreTraffic: {
                        ...measurement.evaluatorKeyStoreTraffic,
                        distinctReadByteLength: 63,
                    },
                },
                measurement.caseIdentifier,
            ),
        ).toThrow(/store accounting/u);
        expect(() =>
            validateDesktopBrowserEvaluatorReplayMeasurement(
                {
                    ...measurement,
                    canonicalReplayCarrierTraffic: {
                        ...measurement.canonicalReplayCarrierTraffic,
                        boardIngressByteLength: 47,
                    },
                },
                measurement.caseIdentifier,
            ),
        ).toThrow(/carrier accounting/u);
        expect(() =>
            validateDesktopBrowserEvaluatorReplayMeasurement(
                {
                    ...measurement,
                    boundaryBufferTraffic: {
                        ...measurement.boundaryBufferTraffic,
                        bufferCount: 2,
                    },
                    evaluatorKeyStoreTraffic: {
                        ...measurement.evaluatorKeyStoreTraffic,
                        readCount: 0,
                    },
                    schedulerYieldCount: 0,
                },
                measurement.caseIdentifier,
            ),
        ).toThrow(/store accounting/u);
    });

    it('refuses inconsistent boundary, scheduler, and memory observations', () => {
        const measurement = validMeasurement();
        expect(() =>
            validateDesktopBrowserEvaluatorReplayMeasurement(
                {
                    ...measurement,
                    boundaryBufferTraffic: {
                        ...measurement.boundaryBufferTraffic,
                        totalByteLength: 159,
                    },
                },
                measurement.caseIdentifier,
            ),
        ).toThrow(/boundary-buffer accounting/u);
        expect(() =>
            validateDesktopBrowserEvaluatorReplayMeasurement(
                { ...measurement, schedulerYieldCount: 3 },
                measurement.caseIdentifier,
            ),
        ).toThrow(/scheduler accounting/u);
        expect(() =>
            validateDesktopBrowserEvaluatorReplayMeasurement(
                {
                    ...measurement,
                    wasmMemory: {
                        ...measurement.wasmMemory,
                        peakByteLength: 131_072,
                    },
                },
                measurement.caseIdentifier,
            ),
        ).toThrow(/WASM-memory accounting/u);
    });

    it('refuses non-exact numbers and mismatched case identifiers', () => {
        const measurement = validMeasurement();
        expect(() =>
            validateDesktopBrowserEvaluatorReplayMeasurement(
                {
                    ...measurement,
                    evaluatorKeyStoreTraffic: {
                        ...measurement.evaluatorKeyStoreTraffic,
                        requestedReadByteLength: Number.MAX_SAFE_INTEGER + 1,
                    },
                },
                measurement.caseIdentifier,
            ),
        ).toThrow(/nonnegative exact integer/u);
        expect(() =>
            validateDesktopBrowserEvaluatorReplayMeasurement(
                measurement,
                'different-case',
            ),
        ).toThrow(/mismatched case identifier/u);
        expect(() =>
            validateDesktopBrowserEvaluatorReplayMeasurement(
                { ...measurement, elapsedMilliseconds: Number.NaN },
                measurement.caseIdentifier,
            ),
        ).toThrow(/nonnegative finite number/u);
    });

    it('requires exact lowercase build, input, and public-output hashes', () => {
        const measurement = validMeasurement();
        expect(() =>
            validateDesktopBrowserEvaluatorReplayMeasurement(
                {
                    ...measurement,
                    measurementIdentity: {
                        ...measurement.measurementIdentity,
                        packagedWasmSha256: 'AA'.repeat(32),
                    },
                },
                measurement.caseIdentifier,
            ),
        ).toThrow(/lowercase SHA-256 hexadecimal digest/u);
        expect(() =>
            validateDesktopBrowserEvaluatorReplayMeasurement(
                {
                    ...measurement,
                    measurementIdentity: {
                        ...measurement.measurementIdentity,
                        inputCorpusHash: '88'.repeat(63),
                    },
                },
                measurement.caseIdentifier,
            ),
        ).toThrow(/lowercase Hash512 hexadecimal digest/u);
        expect(() =>
            validateDesktopBrowserEvaluatorReplayMeasurement(
                {
                    ...measurement,
                    publicOutputHashes: {
                        canonicalReplayCarrierSha512: 'not-a-hash',
                    },
                },
                measurement.caseIdentifier,
            ),
        ).toThrow(/lowercase SHA-512 hexadecimal digest/u);
    });

    it('fails closed when no production case is registered', async () => {
        await expect(
            measureProductionDesktopBrowserEvaluatorReplayCase(
                [],
                'selected-evaluator-replay',
            ),
        ).rejects.toThrow(/No production evaluator-replay measurement case/u);
    });

    it('requires unambiguous lowercase kebab-case identifiers', () => {
        expect(
            requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier(
                productionDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier,
            ),
        ).toBe('selected-complete-action');
        for (const malformedIdentifier of [
            '',
            'Selected-evaluator-replay',
            'selected_evaluator_replay',
            'selected--evaluator',
            ' selected-evaluator',
        ]) {
            expect(() =>
                requireDesktopBrowserEvaluatorReplayMeasurementCaseIdentifier(
                    malformedIdentifier,
                ),
            ).toThrow(/lowercase kebab-case/u);
        }
    });
});
