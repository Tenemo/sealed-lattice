import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import type { PackageManagerRunner } from '#tools/ci/package-manager-runner';
import {
    buildCheckGatingLanes,
    buildCheckParallelLanes,
    buildProgressLanePlans,
    formatValidationSummary,
    parseCheckArguments,
    redrawEnabledForProgressMode,
} from '#tools/ci/run-check';

const packageManagerRunner: PackageManagerRunner = {
    command: process.execPath,
    commandArgumentsPrefix: ['pnpm.cjs'],
    kind: 'pnpm',
};

describe('check runner arguments', () => {
    it('uses automatic progress rendering by default', () => {
        expect(parseCheckArguments([])).toEqual({
            progressMode: 'auto',
        });
    });

    it('accepts explicit progress rendering modes', () => {
        expect(parseCheckArguments(['--progress=always'])).toEqual({
            progressMode: 'always',
        });
        expect(parseCheckArguments(['--progress', 'never'])).toEqual({
            progressMode: 'never',
        });
        expect(parseCheckArguments(['--', '--progress=always'])).toEqual({
            progressMode: 'always',
        });
    });

    it('rejects unknown check arguments and progress modes', () => {
        expect(() => parseCheckArguments(['--progress=sometimes'])).toThrow(
            'Usage: run-check.ts [--progress=auto|always|never].',
        );
        expect(() => parseCheckArguments(['--unknown'])).toThrow(
            'Usage: run-check.ts [--progress=auto|always|never].',
        );
    });

    it('does not redraw forced progress on a non-terminal stream', () => {
        expect(redrawEnabledForProgressMode('always', true)).toBe(true);
        expect(redrawEnabledForProgressMode('always', false)).toBe(false);
        expect(redrawEnabledForProgressMode('auto', false)).toBeUndefined();
        expect(redrawEnabledForProgressMode('never', true)).toBe(false);
    });

    it('runs prebuilt Vitest projects without rebuilding the workspace', () => {
        const nodeLanes = buildCheckParallelLanes(packageManagerRunner).filter(
            (lane) => lane.name.startsWith('Node tests'),
        );
        expect(nodeLanes).toHaveLength(2);
        for (const lane of nodeLanes) {
            expect(lane.commands).toHaveLength(1);
            expect(lane.commands[0]?.args).toContain('vitest');
            expect(lane.commands[0]?.args).not.toContain('build');
        }
    });

    it('builds once and provides fresh-checkout duration estimates for every lane', () => {
        const lanes = [
            ...buildCheckGatingLanes(packageManagerRunner),
            ...buildCheckParallelLanes(packageManagerRunner),
        ];
        const buildCommands = lanes.flatMap((lane) =>
            lane.commands.filter(
                (command) =>
                    command.args.includes('build') ||
                    command.args.includes('build:wasm'),
            ),
        );
        expect(buildCommands).toHaveLength(1);
        expect(buildCommands[0]?.description).toBe('Build workspace packages');

        const plans = buildProgressLanePlans(lanes, {
            commandDurationMilliseconds: new Map(),
            laneDurationMilliseconds: new Map(),
            laneProgress: new Map(),
        });
        expect(plans).toHaveLength(lanes.length);
        expect(
            plans.every(
                (plan) =>
                    plan.expectedDurationMilliseconds !== undefined &&
                    plan.expectedDurationMilliseconds > 0,
            ),
        ).toBe(true);
    });

    it('keeps visible pre-commit progress with a terminal and its controlling-terminal fallback', () => {
        const hookLines = readFileSync(
            new URL('../../../.husky/pre-commit', import.meta.url),
            'utf8',
        )
            .replace(/\r/g, '')
            .trim()
            .split('\n');

        expect(hookLines).toEqual([
            'if [ -t 1 ]; then',
            '    pnpm run check -- --progress=always',
            'elif { exec 3>/dev/tty; } 2>/dev/null; then',
            '    pnpm run check -- --progress=always >&3 2>&1',
            '    hook_status=$?',
            '    exec 3>&-',
            '    exit "$hook_status"',
            'else',
            '    pnpm run check -- --progress=never',
            'fi',
        ]);
    });
});

describe('check validation summary', () => {
    it('reports every successful lane and the persisted expected duration', () => {
        expect(
            formatValidationSummary(
                [
                    {
                        durationMilliseconds: 1_234,
                        exitCode: 0,
                        name: 'Build workspace packages',
                        status: 'passed',
                    },
                    {
                        durationMilliseconds: 89,
                        exitCode: 0,
                        name: 'Lint',
                        status: 'passed',
                    },
                ],
                {
                    failureDetails: [],
                    previousSuccessfulDurationMilliseconds: 65_432,
                },
            ),
        ).toEqual([
            '',
            'Validation summary',
            '  PASS      1.2s  Build workspace packages',
            '  PASS      0.1s  Lint',
            '',
            'All validation lanes passed.',
            'Expected duration from previous successful check: 1m05s.',
        ]);
    });

    it('reports failed and stopped lanes with actionable failure context', () => {
        expect(
            formatValidationSummary(
                [
                    {
                        durationMilliseconds: 12_345,
                        exitCode: 7,
                        name: 'Rust kernel',
                        status: 'failed',
                    },
                    {
                        durationMilliseconds: 4_321,
                        exitCode: 1,
                        name: 'Node tests',
                        status: 'stopped',
                    },
                ],
                {
                    failureDetails: [
                        {
                            commandDescription: 'cargo clippy',
                            exitCode: 7,
                            laneName: 'Rust kernel',
                            logPath: 'logs/rust-kernel.log',
                            recentOutputLines: [
                                'error: readable failure context',
                            ],
                        },
                    ],
                    runLogDirectoryPath: 'logs/check-run',
                },
            ),
        ).toEqual([
            '',
            'Validation summary',
            '  FAIL     12.3s  Rust kernel',
            '  STOP      4.3s  Node tests',
            '',
            'Failed: Rust kernel (1 other lane(s) stopped early).',
            'Per-lane logs: logs/check-run',
            '',
            'Failure detail: Rust kernel',
            'Command: cargo clippy',
            'Exit code: 7',
            'Log: logs/rust-kernel.log',
            'Recent output:',
            '  error: readable failure context',
        ]);
    });
});
