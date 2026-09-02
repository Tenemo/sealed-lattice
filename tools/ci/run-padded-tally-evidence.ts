import { mkdir, open, unlink } from 'node:fs/promises';
import path from 'node:path';

import { runWithLocalRunLog } from './local-run-log.js';
import { resolvePackageManagerRunner } from './package-manager-runner.js';
import { createProcessTreeMemoryGuard } from './process-tree-memory-guard.js';
import {
    createPackageManagerCommand,
    runCommandAndCaptureOutput,
    runCommandsInSeries,
} from './run-command.js';

import {
    manualEvidenceCases,
    resolveManualEvidenceCase,
} from '#tests/manual-evidence-registry.js';

const paddedTallyEvidenceCases = manualEvidenceCases.filter(
    (evidenceCase) => evidenceCase.runnerKind === 'vitest-browser',
);
const usage = `Usage: run-padded-tally-evidence.ts <${paddedTallyEvidenceCases
    .map((evidenceCase) => evidenceCase.identifier)
    .join('|')}>.`;
const repositoryRootPath = path.resolve(import.meta.dirname, '..', '..');
const lockDirectoryPath = path.join(
    repositoryRootPath,
    'temp',
    'test-checkpoints',
);
const lockFilePath = path.join(lockDirectoryPath, 'padded-tally-evidence.lock');
const memorySampleIntervalMilliseconds = 2_000;

const acquireSerializationLock = async (): Promise<() => Promise<void>> => {
    await mkdir(lockDirectoryPath, { recursive: true });
    let handle;
    try {
        handle = await open(lockFilePath, 'wx');
    } catch {
        throw new Error(
            `Another padded-tally evidence run owns ${lockFilePath}.`,
        );
    }
    await handle.writeFile(
        JSON.stringify({
            processIdentifier: process.pid,
            startedAtIso: new Date().toISOString(),
        }),
        'utf8',
    );
    await handle.sync();
    await handle.close();
    return async () => unlink(lockFilePath);
};

const requireSingleCase = (arguments_: readonly string[]): string => {
    if (
        arguments_.length !== 1 ||
        arguments_[0] === undefined ||
        arguments_[0].startsWith('-')
    ) {
        throw new Error(usage);
    }
    return arguments_[0];
};

const main = async (): Promise<void> => {
    const processArguments = process.argv.slice(2);
    const rawArguments =
        processArguments[0] === '--'
            ? processArguments.slice(1)
            : processArguments;
    const evidenceCase = resolveManualEvidenceCase(
        requireSingleCase(rawArguments),
    );
    if (evidenceCase.runnerKind !== 'vitest-browser') {
        throw new Error(usage);
    }
    const releaseLock = await acquireSerializationLock();
    try {
        await runWithLocalRunLog(
            {
                commandLineArguments: rawArguments,
                lanes: [evidenceCase.testName],
                resourceSampleIntervalMilliseconds:
                    memorySampleIntervalMilliseconds,
                scriptName: `evidence-${evidenceCase.identifier}`,
            },
            async (runLog) => {
                const packageManagerRunner = resolvePackageManagerRunner();
                const environment = { ...process.env };
                for (const registeredCase of paddedTallyEvidenceCases) {
                    environment[registeredCase.browserEnvironmentVariable] =
                        registeredCase.identifier === evidenceCase.identifier
                            ? '1'
                            : '0';
                }
                const buildExitCode = await runCommandsInSeries(
                    [
                        createPackageManagerCommand(
                            'Build the padded-tally evidence workspace',
                            ['run', 'build'],
                            {
                                env: environment,
                                logFileSlug: 'build',
                                packageManagerRunner,
                            },
                        ),
                    ],
                    { outputMode: 'inherit', runLog },
                );
                if (buildExitCode !== 0) {
                    process.exitCode = buildExitCode;
                    return;
                }
                const testArguments = [
                    '--project',
                    'browser-desktop',
                    '--testNamePattern',
                    evidenceCase.testName,
                    evidenceCase.testFile,
                ];
                const inventory = await runCommandAndCaptureOutput(
                    createPackageManagerCommand(
                        'Validate the padded-tally evidence selector',
                        ['exec', 'vitest', 'list', ...testArguments],
                        {
                            env: environment,
                            logFileSlug: 'test-inventory',
                            packageManagerRunner,
                        },
                    ),
                    { runLog },
                );
                if (
                    inventory.exitCode !== 0 ||
                    inventory.terminationSignal !== null ||
                    !inventory.stdout.includes(evidenceCase.testName)
                ) {
                    throw new Error(
                        'The padded-tally evidence selector matched zero tests.',
                    );
                }
                const abortController = new AbortController();
                const observer = createProcessTreeMemoryGuard({
                    abortController,
                    byteLimit: evidenceCase.memoryLimitByteLength,
                    runLog,
                    sampleIntervalMilliseconds:
                        memorySampleIntervalMilliseconds,
                });
                const exitCode = await runCommandsInSeries(
                    [
                        createPackageManagerCommand(
                            evidenceCase.testName,
                            ['exec', 'vitest', '--run', ...testArguments],
                            {
                                env: environment,
                                logFileSlug: 'padded-tally-evidence',
                                packageManagerRunner,
                            },
                        ),
                    ],
                    {
                        observer,
                        outputMode: 'inherit',
                        runLog,
                        signal: abortController.signal,
                    },
                );
                process.exitCode = exitCode || undefined;
                process.stdout.write(
                    `Padded-tally evidence log: ${runLog.runDirectoryPath}\n`,
                );
            },
        );
    } finally {
        await releaseLock();
    }
};

if (import.meta.main) void main();
