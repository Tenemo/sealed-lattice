import path from 'node:path';

import {
    buildFocusedCommand,
    normalizeFocusedTestFilter,
    runGuardedRustKernelCommands,
    type RustKernelAcceptedSetupRunMode,
} from './run-rust-kernel-accepted-setup-tests.js';
import { verifyFocusedRustLaneSelection } from './rust-focused-lane-selection.js';
import {
    canonicalTestLaneDefinitions,
    rustKernelManualTestLanes,
} from './test-lanes.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

type ManualRustKernelLane = keyof typeof rustKernelManualTestLanes;

const laneLabels = {
    'rust-full-profile-evidence': 'Rust full-profile evidence',
    'rust-measurements': 'Rust measurements',
} as const satisfies Record<ManualRustKernelLane, string>;

const parseArguments = (
    commandArguments: readonly string[],
): {
    readonly focusedFilter?: string;
    readonly lane: ManualRustKernelLane;
    readonly mode: RustKernelAcceptedSetupRunMode;
} => {
    const [rawLane, ...remainingArguments] = commandArguments.filter(
        (argument) => argument !== '--' && argument !== undefined,
    );
    if (!(rawLane !== undefined && rawLane in rustKernelManualTestLanes)) {
        throw new Error(
            'The guarded manual Rust runner requires lane rust-full-profile-evidence or rust-measurements.',
        );
    }
    const lane = rawLane as ManualRustKernelLane;
    let mode: RustKernelAcceptedSetupRunMode = 'accelerated';
    const positionalArguments: string[] = [];
    for (const argument of remainingArguments) {
        if (argument === '--ci') {
            mode = 'ci';
            continue;
        }
        if (argument.startsWith('-')) {
            throw new Error(`Unknown argument ${argument}.`);
        }
        positionalArguments.push(argument);
    }
    if (positionalArguments.length > 1) {
        throw new Error(
            `${canonicalTestLaneDefinitions[lane].rootScript} accepts one optional test or module filter.`,
        );
    }
    const focusedFilter =
        positionalArguments.length === 0
            ? undefined
            : normalizeFocusedTestFilter(positionalArguments[0] ?? '');
    if (focusedFilter === '') {
        throw new Error(
            `${canonicalTestLaneDefinitions[lane].rootScript} requires a non-empty filter.`,
        );
    }

    return { focusedFilter, lane, mode };
};

export const runRustKernelManualTests = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const parsed = parseArguments(rawArguments);
    const label = laneLabels[parsed.lane];
    const testFilters =
        parsed.focusedFilter === undefined
            ? rustKernelManualTestLanes[parsed.lane]
            : [parsed.focusedFilter];
    const targetDirectoryPath = path.resolve(
        process.cwd(),
        'target',
        `${parsed.lane}-${parsed.focusedFilter === undefined ? 'accelerated' : 'focused'}`,
    );
    const commands = testFilters.map((testFilter) => ({
        builtCommand: buildFocusedCommand(testFilter, parsed.mode, {
            logFileSlug: `cargo-test-${parsed.lane}`,
            progressLabel: parsed.lane,
            runName: label,
            targetDirectoryPath,
        }),
        expectedTestFilter: testFilter,
    }));

    if (parsed.focusedFilter !== undefined) {
        verifyFocusedRustLaneSelection({
            environment: commands[0]?.builtCommand.command.env,
            lane: parsed.lane,
            testFilter: parsed.focusedFilter,
        });
    }

    await runGuardedRustKernelCommands({
        commands,
        laneLabel: `${label}${
            parsed.focusedFilter === undefined ? '' : ' focused'
        } (${parsed.mode})`,
        rawArguments: rawArguments.slice(1),
        scriptName: canonicalTestLaneDefinitions[parsed.lane].rootScript,
    });
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void runRustKernelManualTests();
}
