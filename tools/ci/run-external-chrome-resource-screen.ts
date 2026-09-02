import { mkdir, open, readFile, unlink } from 'node:fs/promises';
import path from 'node:path';

import { buildWasmKernel } from './build-wasm-kernel.js';
import { runWithLocalRunLog } from './local-run-log.js';
import { resolvePackageManagerRunner } from './package-manager-runner.js';
import { createProcessTreeMemoryGuard } from './process-tree-memory-guard.js';
import {
    createPackageManagerCommand,
    runCommandsInSeries,
} from './run-command.js';

import { resolveManualEvidenceCase } from '#tests/manual-evidence-registry.js';

const repositoryRootPath = path.resolve(import.meta.dirname, '..', '..');
const evidenceCase = resolveManualEvidenceCase(
    'external-chrome-resource-screen',
);
const memorySampleIntervalMilliseconds = 2_000;
const lockDirectoryPath = path.join(
    repositoryRootPath,
    'temp',
    'test-checkpoints',
);
const lockFilePath = path.join(
    lockDirectoryPath,
    'external-chrome-resource-screen.lock',
);

const acquireSerializationLock = async (): Promise<() => Promise<void>> => {
    await mkdir(lockDirectoryPath, { recursive: true });
    let handle;
    try {
        handle = await open(lockFilePath, 'wx');
    } catch {
        throw new Error(
            `Another external-Chrome resource screen owns ${lockFilePath}.`,
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

const main = async (): Promise<void> => {
    if (evidenceCase.runnerKind !== 'external-chrome') {
        throw new Error('The external-Chrome evidence case is misregistered.');
    }
    if (process.argv.length !== 2) {
        throw new Error(
            'The external-Chrome resource screen takes no arguments.',
        );
    }
    const releaseLock = await acquireSerializationLock();
    try {
        await runWithLocalRunLog(
            {
                commandLineArguments: [],
                lanes: [evidenceCase.testName],
                resourceSampleIntervalMilliseconds:
                    memorySampleIntervalMilliseconds,
                scriptName: 'evidence-external-chrome-resource-screen',
            },
            async (runLog) => {
                const packageManagerRunner = resolvePackageManagerRunner();
                const buildExitCode = await runCommandsInSeries(
                    [
                        createPackageManagerCommand(
                            'Build the external-Chrome resource-screen workspace',
                            ['run', 'build'],
                            {
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
                const attachmentDirectoryPath = path.join(
                    runLog.runDirectoryPath,
                    'attachments',
                    'external-chrome-resource-screen',
                );
                await mkdir(attachmentDirectoryPath, { recursive: true });
                const wasmFilePath = path.join(
                    attachmentDirectoryPath,
                    'resource-screen-kernel.wasm',
                );
                runLog.writeEvent({
                    eventType: 'resource-screen-kernel-build-started',
                });
                const wasmBuild = await buildWasmKernel({
                    outputFilePath: wasmFilePath,
                    resourceScreen: true,
                });
                runLog.writeEvent({
                    details: {
                        hash: wasmBuild.hash,
                        outputFilePath: wasmBuild.outputFilePath,
                    },
                    eventType: 'resource-screen-kernel-build-finished',
                });
                const resultFilePath = path.join(
                    attachmentDirectoryPath,
                    'result.json',
                );
                const abortController = new AbortController();
                const exitCode = await runCommandsInSeries(
                    [
                        createPackageManagerCommand(
                            evidenceCase.testName,
                            [
                                'exec',
                                'tsx',
                                './tools/ci/external-chrome-resource-screen-driver.ts',
                                '--wasm',
                                wasmFilePath,
                                '--result',
                                resultFilePath,
                            ],
                            {
                                logFileSlug: 'external-chrome-resource-screen',
                                packageManagerRunner,
                            },
                        ),
                    ],
                    {
                        observer: createProcessTreeMemoryGuard({
                            abortController,
                            byteLimit: evidenceCase.memoryLimitByteLength,
                            runLog,
                            sampleIntervalMilliseconds:
                                memorySampleIntervalMilliseconds,
                        }),
                        outputMode: 'inherit',
                        runLog,
                        signal: abortController.signal,
                    },
                );
                process.exitCode = exitCode || undefined;
                if (exitCode === 0) {
                    const result: unknown = JSON.parse(
                        await readFile(resultFilePath, 'utf8'),
                    );
                    runLog.writeEvent({
                        details:
                            typeof result === 'object' && result !== null
                                ? (result as Readonly<Record<string, unknown>>)
                                : { malformedResult: true },
                        eventType: 'external-chrome-resource-screen-finished',
                    });
                }
                process.stdout.write(
                    `External-Chrome resource-screen log: ${runLog.runDirectoryPath}\n`,
                );
            },
        );
    } finally {
        await releaseLock();
    }
};

if (import.meta.main) await main();
