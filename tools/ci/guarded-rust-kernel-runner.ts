import path from 'node:path';

import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import {
    createHeavyTestProgressReporter,
    resolveFocusedRustTestRunResult,
} from './heavy-test-progress.js';
import { safeLogSlug, type ActiveLocalRunLog } from './local-run-log.js';
import {
    createProcessMemoryGuard,
    deriveProcessMemoryLimitGigabytes,
    resolveProcessMemoryLimitGigabytes,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import { runCommandsInSeries, type CommandInvocation } from './run-command.js';

const memoryLimitEnvironmentVariable =
    'SEALED_LATTICE_GUARDED_RUST_MEMORY_LIMIT_GIB';
const serializedThreadCount = '1';

type BuiltGuardedRustKernelCommand = Readonly<{
    command: CommandInvocation;
    progressLabel: string;
    setupMessages: readonly string[];
}>;

type GuardedRustKernelCommand = Readonly<{
    builtCommand: BuiltGuardedRustKernelCommand;
    expectedTestFilter?: string;
}>;

export const deriveGuardedRustMemoryLimitGigabytes = (input: {
    readonly freeMemoryGigabytes: number;
    readonly totalMemoryGigabytes: number;
}): number =>
    deriveProcessMemoryLimitGigabytes({
        ...input,
        insufficientFreeMemoryRunDescription: 'Guarded Rust kernel tests',
    });

export const resolveGuardedRustMemoryLimitGigabytes = (input: {
    readonly automaticLimitGigabytes: number;
    readonly environment?: NodeJS.ProcessEnv;
}): number =>
    resolveProcessMemoryLimitGigabytes({
        ...input,
        memoryLimitEnvironmentVariable,
    });

let guardedRustProcessMemoryGuard: ProcessMemoryGuard | undefined;

const getGuardedRustProcessMemoryGuard = (): ProcessMemoryGuard => {
    guardedRustProcessMemoryGuard ??= createProcessMemoryGuard({
        insufficientFreeMemoryRunDescription: 'Guarded Rust kernel tests',
        memoryLimitEnvironmentVariable,
    });

    return guardedRustProcessMemoryGuard;
};

export const buildGuardedRustEnvironment = (input: {
    readonly baseEnvironment?: NodeJS.ProcessEnv;
    readonly targetDirectoryPath: string;
}): NodeJS.ProcessEnv => {
    const environment = {
        ...(input.baseEnvironment ?? process.env),
    };
    delete environment.CARGO_TARGET_DIR;
    delete environment.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS;
    delete environment.SEALED_LATTICE_TEST_CHECKPOINT_ROOT;

    return {
        ...environment,
        CARGO_BUILD_JOBS: serializedThreadCount,
        CARGO_INCREMENTAL: '0',
        CARGO_TARGET_DIR: input.targetDirectoryPath,
        RAYON_NUM_THREADS: serializedThreadCount,
        RUST_BACKTRACE: 'full',
    };
};

const cargoTestArgumentsForGuardedRustFilter = (
    testFilter: string,
    cargoFeatures: readonly string[] = [],
    useReleaseProfile = false,
): readonly string[] => [
    'test',
    '--locked',
    '-p',
    'sealed-lattice-kernel',
    ...(useReleaseProfile ? ['--release'] : []),
    ...(cargoFeatures.length === 0
        ? []
        : ['--features', cargoFeatures.join(',')]),
    testFilter,
    '--',
    '--include-ignored',
    '--nocapture',
    '--test-threads',
    serializedThreadCount,
];

export const buildGuardedRustKernelCommand = (
    testFilter: string,
    input: {
        readonly baseEnvironment?: NodeJS.ProcessEnv;
        readonly logFileSlug: string;
        readonly progressLabel: string;
        readonly runName: string;
        readonly targetDirectoryPath: string;
        readonly cargoFeatures?: readonly string[];
        readonly useReleaseProfile?: boolean;
    },
): BuiltGuardedRustKernelCommand => {
    const memoryLimitGigabytes =
        getGuardedRustProcessMemoryGuard().memoryLimitGigabytes;
    return {
        command: {
            args: cargoTestArgumentsForGuardedRustFilter(
                testFilter,
                input.cargoFeatures ?? [],
                input.useReleaseProfile ?? false,
            ),
            command: 'cargo',
            description: `cargo test ${testFilter} (guarded)`,
            env: buildGuardedRustEnvironment({
                ...(input.baseEnvironment === undefined
                    ? {}
                    : { baseEnvironment: input.baseEnvironment }),
                targetDirectoryPath: input.targetDirectoryPath,
            }),
            logFileSlug: input.logFileSlug,
        },
        progressLabel: input.progressLabel,
        setupMessages: [
            `${input.runName}: filter [${testFilter}], 1 serialized test thread; ` +
                `${input.useReleaseProfile === true ? 'release' : 'test'} profile; hard inherited process-memory ceiling ${memoryLimitGigabytes} GiB.`,
            `Pinned target directory: ${input.targetDirectoryPath}. Incremental compilation: off. Run logs stay under logs/.`,
        ],
    };
};

export const verifyGuardedRustProcessMemoryGuardCommand =
    (): CommandInvocation =>
        getGuardedRustProcessMemoryGuard().buildVerificationCommand();

export const guardRustKernelCommand = (
    command: CommandInvocation,
    memoryLimitBytes?: number,
    diagnosticsPath?: string,
): CommandInvocation => {
    const processMemoryGuard = getGuardedRustProcessMemoryGuard();
    return processMemoryGuard.guardCommand(command, {
        diagnosticsPath,
        memoryLimitBytes:
            memoryLimitBytes ?? processMemoryGuard.memoryLimitBytes,
    });
};

const buildGuardedRustKernelDiagnosticFileNames = (input: {
    readonly commandIndex: number;
    readonly progressLabel: string;
}): Readonly<{
    processMemoryGuard: string;
    testEvents: string;
}> => {
    const commandOrdinal = String(input.commandIndex + 1).padStart(2, '0');
    const diagnosticSlug = safeLogSlug(input.progressLabel);

    return {
        processMemoryGuard: `process-memory-guard-${commandOrdinal}-${diagnosticSlug}.jsonl`,
        testEvents: `${commandOrdinal}-${diagnosticSlug}.jsonl`,
    };
};

const writeRunnerSetupMessages = (
    runLog: ActiveLocalRunLog,
    setupMessages: readonly string[],
): void => {
    for (const message of setupMessages) {
        console.log(message);
        runLog.writeCombinedOutput(`${message}\n`);
    }
};

export const runGuardedRustKernelCommands = async (input: {
    readonly commands: readonly GuardedRustKernelCommand[];
    readonly laneLabel: string;
    readonly processMemoryGuardAlreadyVerified?: boolean;
    readonly runLog: ActiveLocalRunLog;
}): Promise<void> => {
    const { runLog } = input;
    for (const command of input.commands) {
        writeRunnerSetupMessages(runLog, command.builtCommand.setupMessages);
    }
    process.exitCode = await withLocalHeavyLaneLease({
        action: async () => {
            let exitCode = 0;
            if (input.processMemoryGuardAlreadyVerified !== true) {
                exitCode = await runCommandsInSeries(
                    [verifyGuardedRustProcessMemoryGuardCommand()],
                    { outputMode: 'inherit', runLog },
                );
                if (exitCode !== 0) return exitCode;
            }

            for (const [commandIndex, command] of input.commands.entries()) {
                const diagnosticFileNames =
                    buildGuardedRustKernelDiagnosticFileNames({
                        commandIndex,
                        progressLabel: command.builtCommand.progressLabel,
                    });
                const guardedCommand = guardRustKernelCommand(
                    command.builtCommand.command,
                    undefined,
                    path.join(
                        runLog.runDirectoryPath,
                        'resources',
                        diagnosticFileNames.processMemoryGuard,
                    ),
                );
                const progressReporter = createHeavyTestProgressReporter({
                    eventFilePath: path.join(
                        runLog.runDirectoryPath,
                        'tests',
                        diagnosticFileNames.testEvents,
                    ),
                    label: command.builtCommand.progressLabel,
                    threadCount: 1,
                });
                try {
                    exitCode = await runCommandsInSeries([guardedCommand], {
                        observer: progressReporter.observer,
                        outputMode: 'inherit',
                        runLog,
                        terminalOutputFilter:
                            progressReporter.terminalOutputFilter,
                    });
                } finally {
                    progressReporter.stop();
                }
                if (command.expectedTestFilter !== undefined) {
                    const focusedRunResult = resolveFocusedRustTestRunResult({
                        commandExitCode: exitCode,
                        executedTestCount: progressReporter.executedTestCount(),
                        runnerName: input.laneLabel,
                        testFilter: command.expectedTestFilter,
                    });
                    exitCode = focusedRunResult.exitCode;
                    if (focusedRunResult.failureMessage !== undefined) {
                        console.error(focusedRunResult.failureMessage);
                        runLog.writeCombinedOutput(
                            `${focusedRunResult.failureMessage}\n`,
                        );
                    }
                }
                if (exitCode !== 0) break;
            }
            return exitCode;
        },
        laneLabel: input.laneLabel,
        runLog,
    });
};
