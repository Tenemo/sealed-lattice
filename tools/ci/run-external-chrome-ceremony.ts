import { access, mkdir, open, readFile, unlink } from 'node:fs/promises';
import path from 'node:path';

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
    'external-chrome-complete-ceremony',
);
const defaultCandidateArchivePath = path.join(
    repositoryRootPath,
    'logs',
    '2026-09-03',
    '2026-09-03T06-57-09.078Z-build-padded-tally-candidate-package',
    'attachments',
    'sealed-lattice-wasm-0.0.0.tgz',
);
const memorySampleIntervalMilliseconds = 2_000;
const lockDirectoryPath = path.join(
    repositoryRootPath,
    'temp',
    'test-checkpoints',
);
const lockFilePath = path.join(
    lockDirectoryPath,
    'external-chrome-complete-ceremony.lock',
);

const acquireSerializationLock = async (): Promise<() => Promise<void>> => {
    await mkdir(lockDirectoryPath, { recursive: true });
    let handle;
    try {
        handle = await open(lockFilePath, 'wx');
    } catch {
        throw new Error(
            `Another external-Chrome ceremony owns ${lockFilePath}.`,
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
        throw new Error('The external-Chrome ceremony is misregistered.');
    }
    if (process.argv.length !== 2) {
        throw new Error(
            'The external-Chrome complete ceremony takes no arguments.',
        );
    }
    const candidateArchivePath = path.resolve(
        process.env.SEALED_LATTICE_CANDIDATE_PACKAGE ??
            defaultCandidateArchivePath,
    );
    await access(candidateArchivePath);
    const releaseLock = await acquireSerializationLock();
    try {
        await runWithLocalRunLog(
            {
                commandLineArguments: [],
                lanes: [evidenceCase.testName],
                resourceSampleIntervalMilliseconds:
                    memorySampleIntervalMilliseconds,
                scriptName: 'evidence-external-chrome-complete-ceremony',
            },
            async (runLog) => {
                const attachmentDirectoryPath = path.join(
                    runLog.runDirectoryPath,
                    'attachments',
                    'external-chrome-complete-ceremony',
                );
                await mkdir(attachmentDirectoryPath, { recursive: true });
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
                                './tools/ci/external-chrome-ceremony-driver.ts',
                                '--package',
                                candidateArchivePath,
                                '--result',
                                resultFilePath,
                            ],
                            {
                                logFileSlug:
                                    'external-chrome-complete-ceremony',
                                packageManagerRunner:
                                    resolvePackageManagerRunner(),
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
                        eventType: 'external-chrome-complete-ceremony-finished',
                    });
                }
                process.stdout.write(
                    `External-Chrome complete-ceremony log: ${runLog.runDirectoryPath}\n`,
                );
            },
        );
    } finally {
        await releaseLock();
    }
};

if (import.meta.main) await main();
