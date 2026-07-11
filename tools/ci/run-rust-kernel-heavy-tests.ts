import {
    createFocusedRustTestMatchTracker,
    resolveFocusedRustTestRunResult,
} from './focused-rust-test-match.js';
import { createLocalRunLog, currentProcessExitCode } from './local-run-log.js';
import { createProcessMemoryGuard } from './process-memory-guard.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';
import {
    cargoTestArgumentsForRustKernelHeavy,
    heavyRustKernelTestNamePrefix,
    normalizeRustTestFilter,
} from './rust-kernel-test-arguments.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

export type ParsedRustKernelHeavyArguments = Readonly<{
    testFilter: string;
}>;

const usage = 'Usage: run-rust-kernel-heavy-tests.ts [<heavy Rust test name>].';
const rustKernelHeavyProcessMemoryGuard = createProcessMemoryGuard({
    insufficientFreeMemoryRunDescription: 'Rust kernel heavy tests',
});

export const parseRustKernelHeavyArguments = (
    commandArguments: readonly string[],
): ParsedRustKernelHeavyArguments => {
    const positionalArguments: string[] = [];
    for (const argument of commandArguments) {
        if (argument === '--') {
            continue;
        }
        if (argument.startsWith('-')) {
            throw new Error(`Unknown argument: ${argument}. ${usage}`);
        }
        positionalArguments.push(argument);
    }

    if (positionalArguments.length > 1) {
        throw new Error(`Heavy Rust kernel runs accept one filter. ${usage}`);
    }

    const positionalFilter = positionalArguments[0];
    const testFilter =
        positionalFilter === undefined
            ? heavyRustKernelTestNamePrefix
            : normalizeRustTestFilter(positionalFilter);
    if (!testFilter.startsWith(heavyRustKernelTestNamePrefix)) {
        throw new Error(
            `Heavy Rust kernel filters must start with "${heavyRustKernelTestNamePrefix}". ${usage}`,
        );
    }

    return { testFilter };
};

export const buildRustKernelHeavyTestCommand = (
    parsedArguments: ParsedRustKernelHeavyArguments,
): CommandInvocation =>
    rustKernelHeavyProcessMemoryGuard.guardCommand({
        args: cargoTestArgumentsForRustKernelHeavy(parsedArguments.testFilter),
        command: 'cargo',
        description: `cargo test Rust kernel heavy (${parsedArguments.testFilter})`,
        env: {
            ...process.env,
            CARGO_BUILD_JOBS: '1',
            CARGO_INCREMENTAL: '0',
            RAYON_NUM_THREADS: '1',
            SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE: '1',
            SEALED_LATTICE_TRUSTEE_PROOF_LIMB_BATCH_SIZE: '1',
        },
        logFileSlug: 'cargo-test-rust-kernel-heavy',
    });

export const buildRustKernelHeavyProcessMemoryGuardVerificationCommand =
    (): CommandInvocation =>
        rustKernelHeavyProcessMemoryGuard.buildVerificationCommand();

export const runRustKernelHeavyTests = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const parsedArguments = parseRustKernelHeavyArguments(rawArguments);
    const runLog = await createLocalRunLog({
        commandLineArguments: rawArguments,
        lanes: ['Rust kernel heavy'],
        scriptName: 'test:rust:kernel:heavy',
    });
    const testMatchTracker = createFocusedRustTestMatchTracker();
    let exitCode: number | undefined;

    try {
        exitCode = await runCommandsInSeries(
            [buildRustKernelHeavyProcessMemoryGuardVerificationCommand()],
            {
                outputMode: 'inherit',
                runLog,
            },
        );
        if (exitCode !== 0) {
            process.exitCode = exitCode;
            return;
        }

        exitCode = await runCommandsInSeries(
            [buildRustKernelHeavyTestCommand(parsedArguments)],
            {
                observer: testMatchTracker.observer,
                outputMode: 'inherit',
                runLog,
            },
        );
        const runResult = resolveFocusedRustTestRunResult({
            commandExitCode: exitCode,
            matchedTestCount: testMatchTracker.matchedTestCount(),
            runnerName: 'Rust kernel heavy',
            testFilter: parsedArguments.testFilter,
        });
        exitCode = runResult.exitCode;
        if (runResult.failureMessage !== undefined) {
            console.error(runResult.failureMessage);
            runLog.writeCombinedOutput(`${runResult.failureMessage}\n`);
        }
        process.exitCode = exitCode;
    } finally {
        await runLog.finish({
            exitCode: exitCode ?? currentProcessExitCode(),
        });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void runRustKernelHeavyTests();
}
