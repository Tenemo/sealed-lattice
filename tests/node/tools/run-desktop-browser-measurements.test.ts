import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    buildDesktopBrowserMeasurementCommand,
    buildDesktopBrowserMeasurementGuardVerificationCommand,
    desktopBrowserMeasurementArtifactNames,
    deriveDesktopBrowserProcessMemoryMeasurement,
    parseDesktopBrowserMeasurementArguments,
} from '#tools/ci/run-desktop-browser-measurements';

describe('Desktop-browser measurement runner', () => {
    it('derives baseline-to-peak resident growth from completed guard diagnostics', () => {
        const diagnostics = [
            {
                eventType: 'guard-started',
                memoryLimitBytes: 8_000_000_000,
            },
            {
                eventType: 'resource-sample',
                observedPeakProcessTreeResidentMemoryBytes: 125_000_000,
                processTreeResidentMemoryBytes: 125_000_000,
            },
            {
                eventType: 'resource-sample',
                observedPeakProcessTreeResidentMemoryBytes: 620_000_000,
                processTreeResidentMemoryBytes: 620_000_000,
            },
            {
                eventType: 'resource-sample',
                observedPeakProcessTreeResidentMemoryBytes: 620_000_000,
                processTreeResidentMemoryBytes: 410_000_000,
            },
            {
                eventType: 'child-exited',
                observedPeakProcessTreeResidentMemoryBytes: 620_000_000,
            },
        ]
            .map((record) => JSON.stringify(record))
            .join('\n');

        expect(
            deriveDesktopBrowserProcessMemoryMeasurement(
                diagnostics,
                'direct-ballot-fresh',
            ),
        ).toEqual({
            baselineProcessTreeResidentMemoryBytes: 125_000_000,
            caseIdentifier: 'direct-ballot-fresh',
            measurementScope: 'isolated-desktop-chromium-process-tree',
            observedPeakProcessTreeResidentMemoryBytes: 620_000_000,
            processTreeResidentMemoryIncreaseBytes: 495_000_000,
        });
    });

    it('refuses incomplete, malformed, or internally inconsistent diagnostics', () => {
        expect(() =>
            deriveDesktopBrowserProcessMemoryMeasurement(
                'not JSON',
                'direct-ballot-fresh',
            ),
        ).toThrow('not valid JSON');
        expect(() =>
            deriveDesktopBrowserProcessMemoryMeasurement(
                JSON.stringify({ eventType: 'child-exited' }),
                'direct-ballot-fresh',
            ),
        ).toThrow('no process-tree resident-memory sample');
        expect(() =>
            deriveDesktopBrowserProcessMemoryMeasurement(
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
                'direct-ballot-fresh',
            ),
        ).toThrow('peak below the baseline');
    });

    it('selects unique canonical cases in their requested order', () => {
        expect(
            parseDesktopBrowserMeasurementArguments([
                '--',
                '--case-identifier',
                'direct-ballot-fresh',
                '--case-identifier',
                'selected-vss-relation-resumed',
            ]),
        ).toEqual({
            caseIdentifiers: [
                'direct-ballot-fresh',
                'selected-vss-relation-resumed',
            ],
        });
    });

    it('refuses missing, duplicate, malformed, and unsupported case selection', () => {
        expect(() => parseDesktopBrowserMeasurementArguments([])).toThrow(
            'requires at least one',
        );
        expect(() =>
            parseDesktopBrowserMeasurementArguments(['--case-identifier']),
        ).toThrow('kebab-case');
        expect(() =>
            parseDesktopBrowserMeasurementArguments([
                '--case-identifier',
                'DirectBallotFresh',
            ]),
        ).toThrow('kebab-case');
        expect(() =>
            parseDesktopBrowserMeasurementArguments([
                '--case-identifier',
                'direct-ballot-fresh',
                '--case-identifier',
                'direct-ballot-fresh',
            ]),
        ).toThrow('duplicate case identifier');
        expect(() =>
            parseDesktopBrowserMeasurementArguments(['direct-ballot-fresh']),
        ).toThrow('unsupported argument');
    });

    it('guards only the isolated desktop Chromium measurement command', () => {
        const diagnosticsPath = path.resolve(
            'logs',
            'measurement-test',
            'resources.jsonl',
        );
        const command = buildDesktopBrowserMeasurementCommand(
            diagnosticsPath,
            'direct-ballot-fresh',
        );
        expect(command.command).toContain(
            'sealed-lattice-process-memory-guard',
        );
        expect(command.args).toContain('--diagnostics-path');
        expect(command.args).toContain(diagnosticsPath);
        expect(command.args).toContain('chromium-desktop-measurements');
        expect(command.args).toContain(
            'packages/protocol/tests/manual/production-common-proof.browser.measurement.test.ts',
        );
        expect(command.description).toContain('isolated desktop Chromium');
        expect(command.description).toContain('direct-ballot-fresh');
        expect(command.env).toMatchObject({
            SEALED_LATTICE_TEST_PROJECT_LABEL: 'chromium-desktop-measurements',
            VITE_SEALED_LATTICE_DESKTOP_BROWSER_COMMON_PROOF_MEASUREMENT_CASE_IDENTIFIER:
                'direct-ballot-fresh',
        });
        expect(command.logFileSlug).toContain('direct-ballot-fresh');
        expect(
            desktopBrowserMeasurementArtifactNames('direct-ballot-fresh'),
        ).toEqual({
            diagnosticsFileName:
                'process-memory-guard-browser-desktop-measurements-direct-ballot-fresh.jsonl',
            operationMeasurementFileName:
                'desktop-browser-common-proof-direct-ballot-fresh-measurement.json',
            processMemoryMeasurementFileName:
                'desktop-browser-process-memory-direct-ballot-fresh.json',
        });
        expect(
            buildDesktopBrowserMeasurementGuardVerificationCommand().args,
        ).toContain('sealed-lattice-process-memory-guard');
    });
});
