import { describe, expect, it } from 'vitest';

import type { PackageManagerRunner } from '#tools/ci/package-manager-runner';
import {
    buildCheckGatingLanes,
    buildCheckParallelLanes,
    formatValidationSummary,
} from '#tools/ci/run-check';

const packageManagerRunner: PackageManagerRunner = {
    command: process.execPath,
    commandArgumentsPrefix: ['pnpm.cjs'],
    kind: 'pnpm',
};

describe('check runner', () => {
    it('builds once before prebuilt test lanes', () => {
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

        const nodeTestLanes = lanes.filter((lane) =>
            lane.name.startsWith('Node tests'),
        );
        expect(nodeTestLanes).toHaveLength(3);
        for (const lane of nodeTestLanes) {
            expect(lane.commands).toHaveLength(1);
            expect(lane.commands[0]?.args).not.toContain('build');
        }
    });

    it('keeps failures actionable when sibling lanes stop early', () => {
        const summary = formatValidationSummary(
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
                        recentOutputLines: ['error: readable failure context'],
                    },
                ],
                runLogDirectoryPath: 'logs/check-run',
            },
        );

        expect(summary.join('\n')).toContain(
            'Failed: Rust kernel (1 other lane(s) stopped early).',
        );
        expect(summary).toEqual(
            expect.arrayContaining([
                'Per-lane logs: logs/check-run',
                'Command: cargo clippy',
                'Exit code: 7',
                'Log: logs/rust-kernel.log',
                '  error: readable failure context',
            ]),
        );
    });
});
