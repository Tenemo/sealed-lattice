import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    buildDesktopBrowserEvaluatorReplayMeasurementCommand,
    buildDesktopBrowserEvaluatorReplayMeasurementGuardVerificationCommand,
    deriveDesktopBrowserEvaluatorReplayProcessMemoryMeasurement,
    desktopBrowserEvaluatorReplayMeasurementArtifactNames,
    desktopBrowserEvaluatorReplayMeasurementCommandIdentifier,
    parseDesktopBrowserEvaluatorReplayMeasurementArguments,
} from '#tools/ci/run-desktop-browser-evaluator-replay-measurements';

describe('Desktop-browser evaluator-replay measurement runner', () => {
    it('derives baseline-to-peak resident growth from completed diagnostics', () => {
        const diagnostics = [
            {
                eventType: 'resource-sample',
                processTreeResidentMemoryBytes: 140_000_000,
            },
            {
                eventType: 'resource-sample',
                processTreeResidentMemoryBytes: 730_000_000,
            },
            {
                eventType: 'child-exited',
                observedPeakProcessTreeResidentMemoryBytes: 730_000_000,
            },
        ]
            .map((record) => JSON.stringify(record))
            .join('\n');

        expect(
            deriveDesktopBrowserEvaluatorReplayProcessMemoryMeasurement(
                diagnostics,
                'selected-evaluator-replay',
            ),
        ).toEqual({
            baselineProcessTreeResidentMemoryBytes: 140_000_000,
            caseIdentifier: 'selected-evaluator-replay',
            measurementScope: 'isolated-desktop-chromium-process-tree',
            observedPeakProcessTreeResidentMemoryBytes: 730_000_000,
            processTreeResidentMemoryIncreaseBytes: 590_000_000,
        });
    });

    it('refuses malformed, incomplete, and inconsistent diagnostics', () => {
        expect(() =>
            deriveDesktopBrowserEvaluatorReplayProcessMemoryMeasurement(
                'not JSON',
                'selected-evaluator-replay',
            ),
        ).toThrow(/not valid JSON/u);
        expect(() =>
            deriveDesktopBrowserEvaluatorReplayProcessMemoryMeasurement(
                JSON.stringify({ eventType: 'child-exited' }),
                'selected-evaluator-replay',
            ),
        ).toThrow(/no process-tree resident-memory sample/u);
        expect(() =>
            deriveDesktopBrowserEvaluatorReplayProcessMemoryMeasurement(
                [
                    {
                        eventType: 'resource-sample',
                        processTreeResidentMemoryBytes: 200,
                    },
                    {
                        eventType: 'child-exited',
                        observedPeakProcessTreeResidentMemoryBytes: 199,
                    },
                ]
                    .map((record) => JSON.stringify(record))
                    .join('\n'),
                'selected-evaluator-replay',
            ),
        ).toThrow(/peak below the baseline/u);
    });

    it('selects unique canonical cases in requested order', () => {
        expect(
            parseDesktopBrowserEvaluatorReplayMeasurementArguments([
                '--',
                '--case-identifier',
                'selected-evaluator-replay',
                '--case-identifier',
                'selected-evaluator-replay-resumed',
            ]),
        ).toEqual({
            caseIdentifiers: [
                'selected-evaluator-replay',
                'selected-evaluator-replay-resumed',
            ],
        });
    });

    it('refuses missing, duplicate, malformed, and unsupported selections', () => {
        expect(() =>
            parseDesktopBrowserEvaluatorReplayMeasurementArguments([]),
        ).toThrow(/requires at least one/u);
        expect(() =>
            parseDesktopBrowserEvaluatorReplayMeasurementArguments([
                '--case-identifier',
            ]),
        ).toThrow(/kebab-case/u);
        expect(() =>
            parseDesktopBrowserEvaluatorReplayMeasurementArguments([
                '--case-identifier',
                'SelectedEvaluatorReplay',
            ]),
        ).toThrow(/kebab-case/u);
        expect(() =>
            parseDesktopBrowserEvaluatorReplayMeasurementArguments([
                '--case-identifier',
                'selected-evaluator-replay',
                '--case-identifier',
                'selected-evaluator-replay',
            ]),
        ).toThrow(/duplicate case identifier/u);
        expect(() =>
            parseDesktopBrowserEvaluatorReplayMeasurementArguments([
                'selected-evaluator-replay',
            ]),
        ).toThrow(/unsupported argument/u);
    });

    it('guards the isolated desktop Chromium measurement command', () => {
        const diagnosticsPath = path.resolve(
            'logs',
            'measurement-test',
            'evaluator-replay-resources.jsonl',
        );
        const command = buildDesktopBrowserEvaluatorReplayMeasurementCommand(
            diagnosticsPath,
            'selected-evaluator-replay',
        );
        expect(command.command).toContain(
            'sealed-lattice-process-memory-guard',
        );
        expect(command.args).toContain('--diagnostics-path');
        expect(command.args).toContain(diagnosticsPath);
        expect(command.args).toContain('chromium-desktop-measurements');
        expect(command.args).toContain(
            'packages/protocol/tests/manual/production-evaluator-replay.browser.measurement.test.ts',
        );
        expect(command.description).toContain('isolated desktop Chromium');
        expect(command.description).toContain('selected-evaluator-replay');
        expect(command.env).toMatchObject({
            SEALED_LATTICE_TEST_PROJECT_LABEL: 'chromium-desktop-measurements',
            VITE_SEALED_LATTICE_DESKTOP_BROWSER_EVALUATOR_REPLAY_MEASUREMENT_CASE_IDENTIFIER:
                'selected-evaluator-replay',
        });
        expect(command.logFileSlug).toBe(
            desktopBrowserEvaluatorReplayMeasurementCommandIdentifier(
                'selected-evaluator-replay',
            ),
        );
        expect(
            desktopBrowserEvaluatorReplayMeasurementArtifactNames(
                'selected-evaluator-replay',
            ),
        ).toEqual({
            diagnosticsFileName:
                'process-memory-guard-browser-desktop-evaluator-replay-selected-evaluator-replay.jsonl',
            operationMeasurementFileName:
                'desktop-browser-evaluator-replay-selected-evaluator-replay-measurement.json',
            processMemoryMeasurementFileName:
                'desktop-browser-evaluator-replay-process-memory-selected-evaluator-replay.json',
        });
        expect(
            buildDesktopBrowserEvaluatorReplayMeasurementGuardVerificationCommand()
                .args,
        ).toContain('sealed-lattice-process-memory-guard');
    });
});
