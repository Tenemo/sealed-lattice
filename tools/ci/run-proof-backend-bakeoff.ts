import { randomUUID } from 'node:crypto';
import { access, link, mkdir, open, readFile, unlink } from 'node:fs/promises';
import path from 'node:path';

import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import {
    evaluateProofBackendBakeoff,
    proofBackendBakeoffSchedule,
    validateProofBackendBakeoffSample,
    type ProofBackendBakeoffDecision,
    type ProofBackendName,
    type ValidatedProofBackendBakeoffSample,
} from './proof-backend-bakeoff.js';
import {
    runCommandAndCaptureOutput,
    type CapturedCommandResult,
    type CommandInvocation,
} from './run-command.js';

const laneLabel = 'Proof backend bakeoff';
const scriptName = 'test:rust:kernel:proof-backend-bakeoff';
const cargoFeatureName = 'proof-backend-bakeoff';
const cargoPackageName = 'sealed-lattice-kernel';
const focusedTestFilter = 'proof_backend_bakeoff_frozen_fragment';
const resourceSampleIntervalMilliseconds = 100;
const backendEnvironmentVariable =
    'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND';
const sampleOrdinalEnvironmentVariable =
    'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_SAMPLE_ORDINAL';
const resultPathEnvironmentVariable =
    'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_RESULT_PATH';
const exactCommitHashPattern = /^[0-9a-f]{40}$/u;

type RepositoryState = Readonly<{
    commitHash: string;
    treeDirty: boolean;
}>;

type RepositoryCheckpoint = 'after' | 'before' | 'initial';

type CommandExecutor = (
    invocation: CommandInvocation,
    runLog: ActiveLocalRunLog,
) => Promise<CapturedCommandResult>;

export type ProofBackendBakeoffRunnerDependencies = Readonly<{
    executeCommand?: CommandExecutor;
    processMemoryGuard?: ProcessMemoryGuard;
    readRepositoryState?: (
        checkpoint: RepositoryCheckpoint,
        runLog: ActiveLocalRunLog,
    ) => Promise<RepositoryState>;
}>;

export type ProofBackendBakeoffRunResult = Readonly<{
    attachmentPath: string;
    decision: ProofBackendBakeoffDecision;
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

export const buildProofBackendBakeoffEnvironment = (
    input: {
        readonly baseEnvironment?: NodeJS.ProcessEnv;
        readonly targetDirectoryPath?: string;
    } = {},
): NodeJS.ProcessEnv => {
    const environment: NodeJS.ProcessEnv = {
        ...(input.baseEnvironment ?? process.env),
        CARGO_BUILD_JOBS: '1',
        CARGO_INCREMENTAL: '0',
        CARGO_TARGET_DIR:
            input.targetDirectoryPath ??
            path.resolve(process.cwd(), 'target', 'proof-backend-bakeoff'),
        RAYON_NUM_THREADS: '1',
        RUST_BACKTRACE: 'full',
        RUST_TEST_THREADS: '1',
    };
    delete environment[backendEnvironmentVariable];
    delete environment[sampleOrdinalEnvironmentVariable];
    delete environment[resultPathEnvironmentVariable];
    delete environment.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS;
    delete environment.SEALED_LATTICE_TEST_CHECKPOINT_ROOT;
    return environment;
};

export const buildProofBackendBakeoffPrecompileCommand = (
    environment: NodeJS.ProcessEnv,
): CommandInvocation => ({
    args: [...buildCargoArguments(), '--no-run'],
    command: 'cargo',
    description: 'precompile the release proof backend bakeoff fragment',
    env: environment,
    logFileSlug: 'cargo-precompile-proof-backend-bakeoff',
});

export const buildProofBackendBakeoffListCommand = (
    environment: NodeJS.ProcessEnv,
): CommandInvocation => ({
    args: [
        ...buildCargoArguments(),
        focusedTestFilter,
        '--',
        '--ignored',
        '--list',
        '--test-threads',
        '1',
    ],
    command: 'cargo',
    description: 'list the release proof backend bakeoff fragment owner',
    env: environment,
    logFileSlug: 'cargo-list-proof-backend-bakeoff',
});

export const parseProofBackendBakeoffTestInventory = (
    standardOutput: string,
): string => {
    const inventoryLines = standardOutput
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => /: (?:benchmark|test)$/u.test(line));
    if (inventoryLines.length !== 1) {
        throw new Error(
            `The proof backend bakeoff preflight requires exactly one test, but listed ${inventoryLines.length}.`,
        );
    }
    const [inventoryLine] = inventoryLines;
    if (inventoryLine === undefined || !inventoryLine.endsWith(': test')) {
        throw new Error(
            'The proof backend bakeoff preflight did not resolve to a test.',
        );
    }
    const exactTestName = inventoryLine.slice(0, -': test'.length);
    if (
        exactTestName !== focusedTestFilter &&
        !exactTestName.endsWith(`::${focusedTestFilter}`)
    ) {
        throw new Error(
            `The proof backend bakeoff preflight resolved an unexpected test: ${exactTestName}.`,
        );
    }
    return exactTestName;
};

export const buildProofBackendBakeoffSampleCommand = (input: {
    readonly backend: ProofBackendName;
    readonly baseEnvironment: NodeJS.ProcessEnv;
    readonly exactTestName: string;
    readonly resultPath: string;
    readonly sampleOrdinal: 1 | 2 | 3;
}): CommandInvocation => {
    if (!path.isAbsolute(input.resultPath)) {
        throw new Error('The bakeoff result path must be absolute.');
    }
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
        description: `run ${input.backend} proof backend bakeoff sample ${input.sampleOrdinal}`,
        env: {
            ...input.baseEnvironment,
            [backendEnvironmentVariable]: input.backend,
            [sampleOrdinalEnvironmentVariable]: String(input.sampleOrdinal),
            [resultPathEnvironmentVariable]: input.resultPath,
        },
        logFileSlug: `cargo-proof-backend-bakeoff-${input.backend}-${input.sampleOrdinal}`,
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
            description: `read the ${input.checkpoint}-bakeoff repository commit`,
            logFileSlug: `git-proof-backend-bakeoff-${input.checkpoint}-commit`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    const commitHash = commitResult.stdout.trim();
    if (!exactCommitHashPattern.test(commitHash)) {
        throw new Error(
            `The ${input.checkpoint}-bakeoff repository commit is not an exact 40-hex hash.`,
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
            description: `read the ${input.checkpoint}-bakeoff repository status`,
            logFileSlug: `git-proof-backend-bakeoff-${input.checkpoint}-status`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    return {
        commitHash,
        treeDirty: statusResult.stdout.length !== 0,
    };
};

const requireCleanPinnedRepository = (
    repositoryState: RepositoryState,
    checkpoint: RepositoryCheckpoint,
): void => {
    if (repositoryState.treeDirty) {
        throw new Error(
            `The proof backend bakeoff requires a clean repository tree ${checkpoint} measurement.`,
        );
    }
};

const requirePathDoesNotExist = async (filePath: string): Promise<void> => {
    try {
        await access(filePath);
    } catch (error) {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'ENOENT'
        ) {
            return;
        }
        throw error;
    }
    throw new Error(`Refusing to overwrite bakeoff evidence: ${filePath}.`);
};

export const writeJsonAtomicallyAndExclusively = async (
    filePath: string,
    value: unknown,
): Promise<void> => {
    await mkdir(path.dirname(filePath), { recursive: true });
    await requirePathDoesNotExist(filePath);
    const temporaryPath = path.join(
        path.dirname(filePath),
        `.${path.basename(filePath)}.${process.pid}.${randomUUID()}.tmp`,
    );
    const fileHandle = await open(temporaryPath, 'wx');
    let temporaryFileExists = true;
    try {
        await fileHandle.writeFile(`${JSON.stringify(value, null, 2)}\n`, {
            encoding: 'utf8',
        });
        await fileHandle.sync();
        await fileHandle.close();
        await link(temporaryPath, filePath);
        await unlink(temporaryPath);
        temporaryFileExists = false;
    } finally {
        await fileHandle.close().catch(() => undefined);
        if (temporaryFileExists) {
            await unlink(temporaryPath).catch(() => undefined);
        }
    }
};

const parseJsonEvidence = (
    serialized: string,
    description: string,
): unknown => {
    try {
        return JSON.parse(serialized) as unknown;
    } catch (error) {
        throw Object.assign(
            new Error(`${description} is not valid JSON: ${String(error)}`),
            { cause: error },
        );
    }
};

const normalizeJsonValue = (value: unknown): unknown => {
    if (typeof value === 'bigint') {
        return value.toString();
    }
    if (Array.isArray(value)) {
        return value.map(normalizeJsonValue);
    }
    if (typeof value === 'object' && value !== null) {
        return Object.fromEntries(
            Object.entries(value).map(([key, nestedValue]) => [
                key,
                normalizeJsonValue(nestedValue),
            ]),
        );
    }
    return value;
};

const relativeDiagnosticPath = (
    runDirectoryPath: string,
    filePath: string,
): string =>
    path.relative(runDirectoryPath, filePath).split(path.sep).join('/');

export const executeProofBackendBakeoffSequence = async (input: {
    readonly dependencies?: ProofBackendBakeoffRunnerDependencies;
    readonly runLog: ActiveLocalRunLog;
}): Promise<ProofBackendBakeoffRunResult> => {
    const executeCommand =
        input.dependencies?.executeCommand ?? defaultCommandExecutor;
    const processMemoryGuard =
        input.dependencies?.processMemoryGuard ??
        createProcessMemoryGuard({
            insufficientFreeMemoryRunDescription: 'Proof backend bakeoff',
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
    requireCleanPinnedRepository(repositoryStateInitial, 'initial');

    const attachmentDirectoryPath = path.join(
        input.runLog.runDirectoryPath,
        'attachments',
        'proof-backend-bakeoff',
    );
    const sampleDirectoryPath = path.join(attachmentDirectoryPath, 'samples');
    const resourceDirectoryPath = path.join(
        input.runLog.runDirectoryPath,
        'resources',
    );
    await Promise.all([
        mkdir(sampleDirectoryPath, { recursive: true }),
        mkdir(resourceDirectoryPath, { recursive: true }),
    ]);

    const cargoEnvironment = buildProofBackendBakeoffEnvironment();
    await executeRequiredCommand({
        command: buildProofBackendBakeoffPrecompileCommand(cargoEnvironment),
        executeCommand,
        runLog: input.runLog,
    });
    const listResult = await executeRequiredCommand({
        command: buildProofBackendBakeoffListCommand(cargoEnvironment),
        executeCommand,
        runLog: input.runLog,
    });
    const exactTestName = parseProofBackendBakeoffTestInventory(
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
    requireCleanPinnedRepository(repositoryStateBefore, 'before');
    if (
        repositoryStateBefore.commitHash !== repositoryStateInitial.commitHash
    ) {
        throw new Error(
            'The repository commit changed during proof backend bakeoff preflight.',
        );
    }

    const validatedSamples: ValidatedProofBackendBakeoffSample[] = [];
    const sampleArtifacts: Array<
        Readonly<{
            backend: ProofBackendName;
            guardPath: string;
            resultPath: string;
            sampleOrdinal: 1 | 2 | 3;
        }>
    > = [];
    for (const expectedSample of proofBackendBakeoffSchedule) {
        const sampleStem = `${expectedSample.backend}-sample-${expectedSample.sampleOrdinal}`;
        const resultPath = path.join(
            sampleDirectoryPath,
            `${sampleStem}-result.json`,
        );
        const guardPath = path.join(
            resourceDirectoryPath,
            `process-memory-guard-${sampleStem}.jsonl`,
        );
        await Promise.all([
            requirePathDoesNotExist(resultPath),
            requirePathDoesNotExist(guardPath),
        ]);
        const sampleCommand = buildProofBackendBakeoffSampleCommand({
            backend: expectedSample.backend,
            baseEnvironment: cargoEnvironment,
            exactTestName,
            resultPath,
            sampleOrdinal: expectedSample.sampleOrdinal,
        });
        const guardedSampleCommand = processMemoryGuard.guardCommand(
            sampleCommand,
            {
                diagnosticsPath: guardPath,
                resourceSampleIntervalMilliseconds,
            },
        );
        await executeRequiredCommand({
            command: guardedSampleCommand,
            executeCommand,
            runLog: input.runLog,
        });
        const [serializedResult, guardJsonLines] = await Promise.all([
            readFile(resultPath, 'utf8'),
            readFile(guardPath, 'utf8'),
        ]);
        const validatedSample = validateProofBackendBakeoffSample({
            guardJsonLines,
            result: parseJsonEvidence(
                serializedResult,
                `${expectedSample.backend} sample ${expectedSample.sampleOrdinal} result`,
            ),
        });
        if (
            validatedSample.result.backend !== expectedSample.backend ||
            validatedSample.result.sampleOrdinal !==
                expectedSample.sampleOrdinal
        ) {
            throw new Error(
                `${expectedSample.backend} sample ${expectedSample.sampleOrdinal} emitted a result for a different schedule entry.`,
            );
        }
        validatedSamples.push(validatedSample);
        sampleArtifacts.push({
            backend: expectedSample.backend,
            guardPath: relativeDiagnosticPath(
                input.runLog.runDirectoryPath,
                guardPath,
            ),
            resultPath: relativeDiagnosticPath(
                input.runLog.runDirectoryPath,
                resultPath,
            ),
            sampleOrdinal: expectedSample.sampleOrdinal,
        });
        input.runLog.writeEvent({
            details: {
                backend: expectedSample.backend,
                baselineProcessTreeResidentMemoryByteLength:
                    validatedSample.baselineProcessTreeResidentMemoryByteLength.toString(),
                elapsedNanoseconds:
                    validatedSample.result.elapsedNanoseconds.toString(),
                peakProcessTreeResidentMemoryByteLength:
                    validatedSample.peakProcessTreeResidentMemoryByteLength.toString(),
                proofByteLength:
                    validatedSample.result.canonicalProofByteLength.toString(),
                sampleOrdinal: expectedSample.sampleOrdinal,
            },
            eventType: 'proof-backend-bakeoff-sample-validated',
        });
    }

    const repositoryStateAfter = await readRepositoryState(
        'after',
        input.runLog,
    );
    requireCleanPinnedRepository(repositoryStateAfter, 'after');
    if (repositoryStateAfter.commitHash !== repositoryStateBefore.commitHash) {
        throw new Error(
            'The repository commit changed during the proof backend bakeoff.',
        );
    }

    const evaluation = evaluateProofBackendBakeoff(validatedSamples);
    const attachmentPath = path.join(
        attachmentDirectoryPath,
        'proof-backend-bakeoff-evidence.json',
    );
    await writeJsonAtomicallyAndExclusively(
        attachmentPath,
        normalizeJsonValue({
            arms: {
                packedDeepFri: evaluation.packedDeepFri,
                sumcheckClass: evaluation.sumcheckClass,
            },
            decision: evaluation.decision,
            formatVersion: 1,
            repository: {
                after: repositoryStateAfter,
                before: repositoryStateBefore,
                initial: repositoryStateInitial,
            },
            resourceSampleIntervalMilliseconds,
            sampleArtifacts,
            samples: validatedSamples,
            schedule: proofBackendBakeoffSchedule,
        }),
    );
    input.runLog.writeEvent({
        details: {
            attachmentPath,
            decisionOutcome: evaluation.decision.outcome,
            ...(evaluation.decision.selectedBackend === undefined
                ? {}
                : {
                      selectedBackend: evaluation.decision.selectedBackend,
                  }),
        },
        eventType: 'proof-backend-bakeoff-evaluated',
    });
    const evidenceMessage = `Proof backend bakeoff evidence: ${attachmentPath}\n`;
    process.stdout.write(evidenceMessage);
    input.runLog.writeCombinedOutput(evidenceMessage);

    if (evaluation.decision.outcome === 'ambiguous') {
        throw new Error(
            'The proof backend bakeoff is ambiguous under the required factor-two, three-metric selection margin.',
        );
    }
    return {
        attachmentPath,
        decision: evaluation.decision,
    };
};

export const runProofBackendBakeoff = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const effectiveArguments = rawArguments.filter(
        (argument) => argument !== '--',
    );
    if (effectiveArguments.length !== 0) {
        throw new Error(
            'The proof backend bakeoff runner accepts no arguments.',
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
                action: () => executeProofBackendBakeoffSequence({ runLog }),
                laneLabel,
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    void runProofBackendBakeoff();
}
