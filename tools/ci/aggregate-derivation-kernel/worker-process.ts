import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
    readJsonFile,
    writeJsonFileAtomic,
    type RuntimeBinding,
} from './checkpoints.js';
import type { RunnerConfig, WorkerJob } from './config.js';
import type { BridgeSupportHashes, WorkerResult } from './types.js';

export const workerOutputPrefix = 'AGGREGATE_DERIVATION_KERNEL_WORKER=';

const runnerScriptPath = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    'runner.ts',
);

const workerEnvironment = (): NodeJS.ProcessEnv => {
    const environment: NodeJS.ProcessEnv = { ...process.env };
    for (const key of Object.keys(environment)) {
        if (key.startsWith('SEALED_LATTICE_')) {
            delete environment[key];
        }
    }
    environment.NODE_OPTIONS = [
        environment.NODE_OPTIONS,
        '--max-old-space-size=8192',
    ]
        .filter((option): option is string => option !== undefined)
        .join(' ');

    return environment;
};

const runWorker = async (input: {
    readonly receiver: number;
    readonly runConfigPath: string;
    readonly workerJob: WorkerJob;
    readonly workerOutputDirectory: string;
}): Promise<WorkerResult> => {
    await mkdir(input.workerOutputDirectory, { recursive: true });
    const outputPath = path.join(
        input.workerOutputDirectory,
        `${input.workerJob}-${input.receiver}.json`,
    );
    const tsxPath = path.resolve(
        process.cwd(),
        'node_modules',
        'tsx',
        'dist',
        'cli.mjs',
    );
    const args = [
        tsxPath,
        runnerScriptPath,
        '--worker-job',
        input.workerJob,
        '--receiver',
        String(input.receiver),
        '--run-config',
        input.runConfigPath,
        '--worker-output',
        outputPath,
    ];

    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, args, {
            cwd: process.cwd(),
            env: workerEnvironment(),
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        let stdout = '';
        let stderr = '';
        child.stdout.setEncoding('utf8');
        child.stderr.setEncoding('utf8');
        child.stdout.on('data', (chunk: string) => {
            stdout += chunk;
            process.stdout.write(chunk);
        });
        child.stderr.on('data', (chunk: string) => {
            stderr += chunk;
            process.stderr.write(chunk);
        });
        child.on('error', (error) => {
            reject(error);
        });
        child.on('close', (exitCode) => {
            if (exitCode !== 0) {
                reject(
                    new Error(
                        `${input.workerJob} worker ${input.receiver} failed with exit ${String(exitCode)}. ${stderr.slice(-2000)}`,
                    ),
                );

                return;
            }
            if (!stdout.includes(workerOutputPrefix)) {
                reject(
                    new Error(
                        `${input.workerJob} worker ${input.receiver} did not report completion.`,
                    ),
                );

                return;
            }
            void (async () => {
                try {
                    resolve(await readJsonFile<WorkerResult>(outputPath));
                } catch (error) {
                    reject(
                        error instanceof Error
                            ? error
                            : new Error(String(error)),
                    );
                }
            })();
        });
    });
};

export const runWorkerPool = async (input: {
    readonly receivers: readonly number[];
    readonly runConfigPath: string;
    readonly workerCount: number;
    readonly workerJob: WorkerJob;
    readonly workerOutputDirectory: string;
}): Promise<readonly WorkerResult[]> => {
    const results: WorkerResult[] = [];
    let nextReceiverIndex = 0;
    const workerCount = Math.min(input.workerCount, input.receivers.length);
    await Promise.all(
        Array.from({ length: workerCount }, async (_unused, workerIndex) => {
            while (true) {
                const receiver = input.receivers[nextReceiverIndex];
                nextReceiverIndex += 1;
                if (receiver === undefined) {
                    break;
                }
                console.log(
                    `${input.workerJob} started: receiver=${receiver}, worker=${workerIndex + 1}`,
                );
                const result = await runWorker({
                    receiver,
                    runConfigPath: input.runConfigPath,
                    workerJob: input.workerJob,
                    workerOutputDirectory: input.workerOutputDirectory,
                });
                results.push(result);
                console.log(
                    `${input.workerJob} finished: receiver=${receiver}, worker=${workerIndex + 1}`,
                );
            }
        }),
    );

    return results.sort((left, right) => left.receiver - right.receiver);
};

export const writeWorkerRunConfig = async (input: {
    readonly checkpointDir: string;
    readonly config: RunnerConfig;
    readonly forceRecompute?: readonly string[];
    readonly runtime: RuntimeBinding;
    readonly resumeCheckpoints?: boolean;
    readonly setupPackage?: Record<string, unknown>;
    readonly supportHashes?: BridgeSupportHashes;
}): Promise<string> => {
    const runConfig = {
        checkpointDir: input.config.checkpointDir,
        dependencyArtifactHash: input.runtime.dependencyArtifactHash,
        forceRecompute: input.forceRecompute ?? [
            ...input.config.forceRecompute,
        ],
        kernelHash: input.runtime.kernelHash,
        requireCheckpoints: input.config.requireCheckpoints,
        resumeCheckpoints:
            input.resumeCheckpoints ?? input.config.resumeCheckpoints,
        setupPackage: input.setupPackage,
        sourceFingerprint: input.runtime.sourceFingerprint,
        supportHashes: input.supportHashes,
        target: input.config.target,
    };
    const filePath = path.join(
        input.checkpointDir,
        `aggregate-derivation-kernel-run-${process.pid}-${randomUUID()}.json`,
    );
    await writeJsonFileAtomic(filePath, runConfig);

    return filePath;
};
