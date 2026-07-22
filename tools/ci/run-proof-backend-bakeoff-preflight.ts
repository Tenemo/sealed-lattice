import { mkdir } from 'node:fs/promises';
import path from 'node:path';

import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import {
    runCommandAndCaptureOutput,
    type CapturedCommandResult,
    type CommandInvocation,
} from './run-command.js';
import {
    buildProofBackendBakeoffEnvironment,
    buildProofBackendBakeoffPrecompileCommand,
    writeJsonAtomicallyAndExclusively,
} from './run-proof-backend-bakeoff.js';

const laneLabel = 'Proof backend bakeoff preflight';
const scriptName = 'test:rust:kernel:proof-backend-bakeoff-preflight';
const cargoFeatureName = 'proof-backend-bakeoff';
const cargoPackageName = 'sealed-lattice-kernel';
const moduleTestFilter = 'bgv::proof_suite::proof_backend_bakeoff::tests';
const measurementTestName = `${moduleTestFilter}::proof_backend_bakeoff_frozen_fragment`;
const resourceSampleIntervalMilliseconds = 100;
const exactCommitHashPattern = /^[0-9a-f]{40}$/u;

export const proofBackendBakeoffPreflightTestNames = [
    `${moduleTestFilter}::frozen_backend_binding_vectors_regenerate_from_exact_columns_and_profiles`,
    `${moduleTestFilter}::packed_deep_fri_fresh_verifier_has_no_witness_side_channel`,
    `${moduleTestFilter}::sumcheck_class_fresh_verifier_has_no_witness_side_channel`,
] as const;

type ProofBackendBakeoffPreflightTestName =
    (typeof proofBackendBakeoffPreflightTestNames)[number];

const preflightTestFileSlugs = {
    [proofBackendBakeoffPreflightTestNames[0]]: 'binding-vectors',
    [proofBackendBakeoffPreflightTestNames[1]]:
        'packed-deep-fri-fresh-verifier',
    [proofBackendBakeoffPreflightTestNames[2]]: 'sumcheck-class-fresh-verifier',
} as const satisfies Record<ProofBackendBakeoffPreflightTestName, string>;

type RepositoryState = Readonly<{
    commitHash: string;
    treeDirty: boolean;
}>;

type RepositoryCheckpoint = 'after' | 'before' | 'initial';

type CommandExecutor = (
    invocation: CommandInvocation,
    runLog: ActiveLocalRunLog,
) => Promise<CapturedCommandResult>;

export type ProofBackendBakeoffPreflightRunnerDependencies = Readonly<{
    executeCommand?: CommandExecutor;
    processMemoryGuard?: ProcessMemoryGuard;
    readRepositoryState?: (
        checkpoint: RepositoryCheckpoint,
        runLog: ActiveLocalRunLog,
    ) => Promise<RepositoryState>;
}>;

export type ProofBackendBakeoffPreflightRunResult = Readonly<{
    attachmentPath: string;
}>;

const buildCargoArguments = (): readonly string[] => [
    'test',
    '--locked',
    '--release',
    '-p',
    cargoPackageName,
    '--features',
    cargoFeatureName,
    '--lib',
];

export const buildProofBackendBakeoffPreflightListCommand = (
    environment: NodeJS.ProcessEnv,
): CommandInvocation => ({
    args: [
        ...buildCargoArguments(),
        moduleTestFilter,
        '--',
        '--ignored',
        '--list',
        '--test-threads',
        '1',
    ],
    command: 'cargo',
    description: 'list the proof backend bakeoff ignored owners',
    env: environment,
    logFileSlug: 'cargo-list-proof-backend-bakeoff-preflight',
});

const listedInventoryLines = (standardOutput: string): readonly string[] =>
    standardOutput
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => /: (?:benchmark|test)$/u.test(line));

export const parseProofBackendBakeoffPreflightInventory = (
    standardOutput: string,
): readonly ProofBackendBakeoffPreflightTestName[] => {
    const inventoryLines = listedInventoryLines(standardOutput);
    if (inventoryLines.length === 0) {
        throw new Error(
            'The proof backend bakeoff preflight inventory selected zero tests.',
        );
    }
    const benchmarkLines = inventoryLines.filter((line) =>
        line.endsWith(': benchmark'),
    );
    if (benchmarkLines.length !== 0) {
        throw new Error(
            `The proof backend bakeoff preflight inventory unexpectedly selected benchmarks: ${benchmarkLines.join(', ')}.`,
        );
    }
    const actualTestNames = inventoryLines.map((line) =>
        line.slice(0, -': test'.length),
    );
    const duplicateTestNames = actualTestNames.filter(
        (testName, index) => actualTestNames.indexOf(testName) !== index,
    );
    if (duplicateTestNames.length !== 0) {
        throw new Error(
            `The proof backend bakeoff preflight inventory contains duplicate tests: ${[...new Set(duplicateTestNames)].join(', ')}.`,
        );
    }

    const expectedModuleTestNames = [
        ...proofBackendBakeoffPreflightTestNames,
        measurementTestName,
    ];
    const actualTestNameSet = new Set(actualTestNames);
    const expectedTestNameSet = new Set(expectedModuleTestNames);
    const missingTestNames = expectedModuleTestNames.filter(
        (testName) => !actualTestNameSet.has(testName),
    );
    const extraTestNames = actualTestNames.filter(
        (testName) => !expectedTestNameSet.has(testName),
    );
    if (missingTestNames.length !== 0 || extraTestNames.length !== 0) {
        throw new Error(
            `The proof backend bakeoff ignored-owner inventory does not match its exact registry. Missing: ${missingTestNames.length === 0 ? 'none' : missingTestNames.join(', ')}. Extra: ${extraTestNames.length === 0 ? 'none' : extraTestNames.join(', ')}.`,
        );
    }

    return proofBackendBakeoffPreflightTestNames;
};

const isPreflightTestName = (
    testName: string,
): testName is ProofBackendBakeoffPreflightTestName =>
    proofBackendBakeoffPreflightTestNames.some(
        (expectedTestName) => expectedTestName === testName,
    );

export const buildProofBackendBakeoffPreflightTestCommand = (input: {
    readonly environment: NodeJS.ProcessEnv;
    readonly exactTestName: string;
}): CommandInvocation => {
    if (!isPreflightTestName(input.exactTestName)) {
        throw new Error(
            `The proof backend bakeoff preflight refuses an unregistered test: ${input.exactTestName}.`,
        );
    }
    const testFileSlug = preflightTestFileSlugs[input.exactTestName];
    return {
        args: [
            ...buildCargoArguments(),
            input.exactTestName,
            '--',
            '--exact',
            '--ignored',
            '--nocapture',
            '--test-threads',
            '1',
        ],
        command: 'cargo',
        description: `run proof backend bakeoff preflight ${input.exactTestName}`,
        env: input.environment,
        logFileSlug: `cargo-proof-backend-bakeoff-preflight-${testFileSlug}`,
    };
};

const executeRequiredCommand = async (input: {
    readonly command: CommandInvocation;
    readonly executeCommand: CommandExecutor;
    readonly runLog: ActiveLocalRunLog;
}): Promise<CapturedCommandResult> => {
    const result = await input.executeCommand(input.command, input.runLog);
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        throw new Error(
            `${input.command.description} failed with exit code ${result.exitCode}${
                result.terminationSignal === null
                    ? ''
                    : ` and signal ${result.terminationSignal}`
            }.`,
        );
    }
    return result;
};

const defaultCommandExecutor: CommandExecutor = (invocation, runLog) =>
    runCommandAndCaptureOutput(invocation, {
        echoOutput: true,
        runLog,
    });

const readRepositoryStateWithCommands = async (input: {
    readonly checkpoint: RepositoryCheckpoint;
    readonly executeCommand: CommandExecutor;
    readonly runLog: ActiveLocalRunLog;
}): Promise<RepositoryState> => {
    const commitResult = await executeRequiredCommand({
        command: {
            args: ['rev-parse', '--verify', 'HEAD^{commit}'],
            command: 'git',
            description: `read the ${input.checkpoint}-preflight repository commit`,
            logFileSlug: `git-proof-backend-bakeoff-preflight-${input.checkpoint}-commit`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    const commitHash = commitResult.stdout.trim();
    if (!exactCommitHashPattern.test(commitHash)) {
        throw new Error(
            `The ${input.checkpoint}-preflight repository commit is not an exact 40-hex hash.`,
        );
    }
    const statusResult = await executeRequiredCommand({
        command: {
            args: [
                'status',
                '--porcelain=v1',
                '--untracked-files=all',
                '--ignore-submodules=none',
            ],
            command: 'git',
            description: `read the ${input.checkpoint}-preflight repository status`,
            logFileSlug: `git-proof-backend-bakeoff-preflight-${input.checkpoint}-status`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    return {
        commitHash,
        treeDirty: statusResult.stdout.length !== 0,
    };
};

const requireCleanRepository = (
    repositoryState: RepositoryState,
    checkpoint: RepositoryCheckpoint,
): void => {
    if (repositoryState.treeDirty) {
        throw new Error(
            `The proof backend bakeoff preflight requires a clean repository tree at its ${checkpoint} checkpoint.`,
        );
    }
};

const requireSameCommit = (input: {
    readonly actual: RepositoryState;
    readonly expected: RepositoryState;
    readonly intervalDescription: string;
}): void => {
    if (input.actual.commitHash !== input.expected.commitHash) {
        throw new Error(
            `The repository commit changed ${input.intervalDescription}.`,
        );
    }
};

const relativeDiagnosticPath = (
    runDirectoryPath: string,
    filePath: string,
): string =>
    path.relative(runDirectoryPath, filePath).split(path.sep).join('/');

export const executeProofBackendBakeoffPreflightSequence = async (input: {
    readonly dependencies?: ProofBackendBakeoffPreflightRunnerDependencies;
    readonly runLog: ActiveLocalRunLog;
}): Promise<ProofBackendBakeoffPreflightRunResult> => {
    const configuredTestCount = Array.from(
        proofBackendBakeoffPreflightTestNames,
    ).length;
    if (configuredTestCount !== 3) {
        throw new Error(
            `The proof backend bakeoff preflight requires exactly three configured tests, but received ${configuredTestCount}.`,
        );
    }
    const executeCommand =
        input.dependencies?.executeCommand ?? defaultCommandExecutor;
    const processMemoryGuard =
        input.dependencies?.processMemoryGuard ??
        createProcessMemoryGuard({
            insufficientFreeMemoryRunDescription:
                'Proof backend bakeoff preflight',
            memoryLimitEnvironmentVariable:
                'SEALED_LATTICE_GUARDED_RUST_MEMORY_LIMIT_GIB',
        });
    const readRepositoryState =
        input.dependencies?.readRepositoryState ??
        ((checkpoint: RepositoryCheckpoint, runLog: ActiveLocalRunLog) =>
            readRepositoryStateWithCommands({
                checkpoint,
                executeCommand,
                runLog,
            }));

    const repositoryStateInitial = await readRepositoryState(
        'initial',
        input.runLog,
    );
    requireCleanRepository(repositoryStateInitial, 'initial');

    const cargoEnvironment = buildProofBackendBakeoffEnvironment();
    await executeRequiredCommand({
        command: buildProofBackendBakeoffPrecompileCommand(cargoEnvironment),
        executeCommand,
        runLog: input.runLog,
    });
    const listResult = await executeRequiredCommand({
        command: buildProofBackendBakeoffPreflightListCommand(cargoEnvironment),
        executeCommand,
        runLog: input.runLog,
    });
    const exactTestNames = parseProofBackendBakeoffPreflightInventory(
        listResult.stdout,
    );
    await executeRequiredCommand({
        command: processMemoryGuard.buildVerificationCommand(),
        executeCommand,
        runLog: input.runLog,
    });

    const repositoryStateBefore = await readRepositoryState(
        'before',
        input.runLog,
    );
    requireCleanRepository(repositoryStateBefore, 'before');
    requireSameCommit({
        actual: repositoryStateBefore,
        expected: repositoryStateInitial,
        intervalDescription: 'during proof backend bakeoff preflight inventory',
    });

    const resourceDirectoryPath = path.join(
        input.runLog.runDirectoryPath,
        'resources',
    );
    await mkdir(resourceDirectoryPath, { recursive: true });
    const completedTests: Array<
        Readonly<{
            diagnosticsPath: string;
            testName: ProofBackendBakeoffPreflightTestName;
        }>
    > = [];
    for (const exactTestName of exactTestNames) {
        const testFileSlug = preflightTestFileSlugs[exactTestName];
        const diagnosticsPath = path.join(
            resourceDirectoryPath,
            `process-memory-guard-proof-backend-bakeoff-preflight-${testFileSlug}.jsonl`,
        );
        const guardedCommand = processMemoryGuard.guardCommand(
            buildProofBackendBakeoffPreflightTestCommand({
                environment: cargoEnvironment,
                exactTestName,
            }),
            {
                diagnosticsPath,
                resourceSampleIntervalMilliseconds,
            },
        );
        await executeRequiredCommand({
            command: guardedCommand,
            executeCommand,
            runLog: input.runLog,
        });
        completedTests.push({
            diagnosticsPath: relativeDiagnosticPath(
                input.runLog.runDirectoryPath,
                diagnosticsPath,
            ),
            testName: exactTestName,
        });
        input.runLog.writeEvent({
            details: {
                diagnosticsPath,
                testName: exactTestName,
            },
            eventType: 'proof-backend-bakeoff-preflight-test-completed',
        });
    }

    const repositoryStateAfter = await readRepositoryState(
        'after',
        input.runLog,
    );
    requireCleanRepository(repositoryStateAfter, 'after');
    requireSameCommit({
        actual: repositoryStateAfter,
        expected: repositoryStateBefore,
        intervalDescription: 'during proof backend bakeoff preflight execution',
    });

    const attachmentPath = path.join(
        input.runLog.runDirectoryPath,
        'attachments',
        'proof-backend-bakeoff-preflight-evidence.json',
    );
    await writeJsonAtomicallyAndExclusively(attachmentPath, {
        completedTests,
        formatVersion: 1,
        processMemoryGuard: {
            memoryLimitBytes: processMemoryGuard.memoryLimitBytes,
            memoryLimitGigabytes: processMemoryGuard.memoryLimitGigabytes,
        },
        repository: {
            after: repositoryStateAfter,
            before: repositoryStateBefore,
            initial: repositoryStateInitial,
        },
        resourceSampleIntervalMilliseconds,
    });
    input.runLog.writeEvent({
        details: { attachmentPath },
        eventType: 'proof-backend-bakeoff-preflight-completed',
    });
    const evidenceMessage = `Proof backend bakeoff preflight evidence: ${attachmentPath}\n`;
    process.stdout.write(evidenceMessage);
    input.runLog.writeCombinedOutput(evidenceMessage);

    return { attachmentPath };
};

export const runProofBackendBakeoffPreflight = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const effectiveArguments = rawArguments.filter(
        (argument) => argument !== '--',
    );
    if (effectiveArguments.length !== 0) {
        throw new Error(
            'The proof backend bakeoff preflight runner accepts no arguments.',
        );
    }
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: [laneLabel],
            scriptName,
        },
        async (runLog) => {
            await withLocalHeavyLaneLease({
                action: () =>
                    executeProofBackendBakeoffPreflightSequence({ runLog }),
                laneLabel,
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    void runProofBackendBakeoffPreflight();
}
