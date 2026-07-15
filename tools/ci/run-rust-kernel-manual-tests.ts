import path from 'node:path';

import { runWithLocalRunLog } from './local-run-log.js';
import {
    buildFocusedCommand,
    runGuardedRustKernelCommands,
} from './run-rust-kernel-accepted-setup-tests.js';
import {
    focusedRustLaneScripts,
    fullProfileEvidenceRustTests,
    measurementRustTests,
    verifyFocusedRustLaneSelection,
} from './rust-focused-lane-selection.js';
import { normalizeRustTestFilter } from './rust-kernel-test-arguments.js';

const manualRustKernelTests = {
    'rust-full-profile-evidence': fullProfileEvidenceRustTests,
    'rust-measurements': measurementRustTests,
} as const;

type ManualRustKernelLane = keyof typeof manualRustKernelTests;

const laneLabels = {
    'rust-full-profile-evidence': 'Rust full-profile evidence',
    'rust-measurements': 'Rust measurements',
} as const satisfies Record<ManualRustKernelLane, string>;

const parseArguments = (
    commandArguments: readonly string[],
): {
    readonly focusedFilter?: string;
    readonly lane: ManualRustKernelLane;
} => {
    const [rawLane, ...remainingArguments] = commandArguments.filter(
        (argument) => argument !== '--',
    );
    if (!(rawLane !== undefined && rawLane in manualRustKernelTests)) {
        throw new Error(
            'The guarded manual Rust runner requires lane rust-full-profile-evidence or rust-measurements.',
        );
    }
    const lane = rawLane as ManualRustKernelLane;
    const positionalArguments: string[] = [];
    for (const argument of remainingArguments) {
        if (argument.startsWith('-')) {
            throw new Error(`Unknown argument ${argument}.`);
        }
        positionalArguments.push(argument);
    }
    if (positionalArguments.length > 1) {
        throw new Error(
            `${focusedRustLaneScripts[lane]} accepts one optional test or module filter.`,
        );
    }
    const focusedFilter =
        positionalArguments.length === 0
            ? undefined
            : normalizeRustTestFilter(positionalArguments[0] ?? '');
    if (focusedFilter === '') {
        throw new Error(
            `${focusedRustLaneScripts[lane]} requires a non-empty filter.`,
        );
    }

    return { focusedFilter, lane };
};

export const runRustKernelManualTests = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const requestedLane = rawArguments.find((argument) => argument !== '--');
    const diagnosticLane =
        requestedLane !== undefined && requestedLane in manualRustKernelTests
            ? (requestedLane as ManualRustKernelLane)
            : undefined;
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: [
                diagnosticLane === undefined
                    ? 'Guarded manual Rust kernel'
                    : laneLabels[diagnosticLane],
            ],
            scriptName:
                diagnosticLane === undefined
                    ? 'test:rust:kernel:manual'
                    : focusedRustLaneScripts[diagnosticLane],
        },
        async (runLog) => {
            const parsed = parseArguments(rawArguments);
            const label = laneLabels[parsed.lane];
            const testFilters =
                parsed.focusedFilter === undefined
                    ? manualRustKernelTests[parsed.lane]
                    : [parsed.focusedFilter];
            const targetDirectoryPath = path.resolve(
                process.cwd(),
                'target',
                `${parsed.lane}-${parsed.focusedFilter === undefined ? 'accelerated' : 'focused'}`,
            );
            const commands = testFilters.map((testFilter) => ({
                builtCommand: buildFocusedCommand(testFilter, 'accelerated', {
                    logFileSlug: `cargo-test-${parsed.lane}`,
                    progressLabel: parsed.lane,
                    runName: label,
                    targetDirectoryPath,
                }),
                expectedTestFilter: testFilter,
            }));

            if (parsed.focusedFilter !== undefined) {
                await verifyFocusedRustLaneSelection({
                    environment: commands[0]?.builtCommand.command.env,
                    lane: parsed.lane,
                    runLog,
                    testFilter: parsed.focusedFilter,
                });
            }

            await runGuardedRustKernelCommands({
                commands,
                laneLabel: `${label}${
                    parsed.focusedFilter === undefined ? '' : ' focused'
                } (accelerated)`,
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    void runRustKernelManualTests();
}
