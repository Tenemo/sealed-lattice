import { createHash } from 'node:crypto';
import { copyFile, mkdir, readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import { createLocalRunLog, currentProcessExitCode } from './local-run-log.js';
import {
    runCommandAndCaptureOutput,
    runCommandsInSeries,
    type CommandOutputEvent,
    type CommandRunObserver,
} from './run-command.js';
import { serializeErrorDiagnostic } from './run-log-diagnostics.js';
import { createTestEventWriter } from './test-event-journal.js';

const defaultDurationSeconds = 60;
const fuzzArtifactFilePattern = /^(?:crash|leak|oom|slow-unit|timeout)-/u;
export const foundationParserFuzzToolchain = {
    cargoFuzzVersion: '0.13.2',
    rustToolchain: 'nightly-2026-06-15',
} as const;

export const requireExpectedCargoFuzzVersion = (output: string): void => {
    const reportedVersion = output.trim();
    const expectedVersion = `cargo-fuzz ${foundationParserFuzzToolchain.cargoFuzzVersion}`;
    if (reportedVersion !== expectedVersion) {
        throw new Error(
            `Foundation parser fuzzing requires ${expectedVersion} under Rust ${foundationParserFuzzToolchain.rustToolchain}; received ${reportedVersion.length === 0 ? 'no version output' : reportedVersion}.`,
        );
    }
};

const verifyFoundationParserFuzzToolchain = async (
    workingDirectoryPath: string,
    runLog: Awaited<ReturnType<typeof createLocalRunLog>>,
): Promise<void> => {
    const commandArguments = [
        `+${foundationParserFuzzToolchain.rustToolchain}`,
        'fuzz',
        '--version',
    ];
    const result = await runCommandAndCaptureOutput(
        {
            args: commandArguments,
            command: 'cargo',
            description: 'verify pinned cargo-fuzz version',
            logFileSlug: 'cargo-fuzz-version',
            workingDirectoryPath,
        },
        { runLog },
    );
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        throw new Error(
            `Foundation parser fuzzing requires Rust ${foundationParserFuzzToolchain.rustToolchain} and cargo-fuzz ${foundationParserFuzzToolchain.cargoFuzzVersion}; install them explicitly before running this manual lane. Preflight status ${result.exitCode}, signal ${result.terminationSignal ?? 'none'}. ${result.stderr.trim()}`,
        );
    }
    requireExpectedCargoFuzzVersion(result.stdout);
};

type FuzzProgress = {
    corpusBytes?: number;
    corpusEntries?: number;
    coverageEdges?: number;
    executions?: number;
    executionsPerSecond?: number;
};

const fuzzProgressPattern =
    /#(\d+).*?cov:\s*(\d+).*?corp:\s*(\d+)\/(\d+)b.*?exec\/s:\s*(\d+)/u;

export const parseFuzzProgressLine = (
    line: string,
): FuzzProgress | undefined => {
    const match = fuzzProgressPattern.exec(line);
    if (
        match?.[1] === undefined ||
        match[2] === undefined ||
        match[3] === undefined ||
        match[4] === undefined ||
        match[5] === undefined
    ) {
        return undefined;
    }

    return {
        corpusBytes: Number(match[4]),
        corpusEntries: Number(match[3]),
        coverageEdges: Number(match[2]),
        executions: Number(match[1]),
        executionsPerSecond: Number(match[5]),
    };
};

export const createFuzzProgressObserver = (input: {
    readonly onProgress: (progress: FuzzProgress) => void;
}): CommandRunObserver => {
    const bufferedOutputByStream: Record<
        CommandOutputEvent['streamName'],
        string
    > = {
        stderr: '',
        stdout: '',
    };
    const consumeLine = (line: string): void => {
        const progress = parseFuzzProgressLine(line);
        if (progress !== undefined) input.onProgress(progress);
    };
    const consumeOutput = (event: CommandOutputEvent): void => {
        const combinedOutput = `${bufferedOutputByStream[event.streamName]}${event.chunk}`;
        const lines = combinedOutput.split(/\r?\n/u);
        bufferedOutputByStream[event.streamName] = lines.pop() ?? '';
        for (const line of lines) {
            consumeLine(line);
        }
    };
    const flushOutput = (): void => {
        for (const streamName of ['stdout', 'stderr'] as const) {
            const remainder = bufferedOutputByStream[streamName];
            bufferedOutputByStream[streamName] = '';
            if (remainder.length > 0) consumeLine(remainder);
        }
    };

    return {
        onCommandExit: flushOutput,
        onCommandOutput: consumeOutput,
    };
};

const listFuzzArtifacts = async (
    artifactDirectoryPath: string,
): Promise<ReadonlySet<string>> => {
    try {
        return new Set(
            (await readdir(artifactDirectoryPath, { withFileTypes: true }))
                .filter(
                    (entry) =>
                        entry.isFile() &&
                        fuzzArtifactFilePattern.test(entry.name),
                )
                .map((entry) => entry.name),
        );
    } catch (error) {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'ENOENT'
        ) {
            return new Set();
        }
        throw error;
    }
};

const retainNewFuzzArtifacts = async (input: {
    readonly artifactDirectoryPath: string;
    readonly beforeRun: ReadonlySet<string>;
    readonly runDirectoryPath: string;
}): Promise<readonly Readonly<Record<string, unknown>>[]> => {
    const afterRun = await listFuzzArtifacts(input.artifactDirectoryPath);
    const newArtifactNames = [...afterRun].filter(
        (artifactName) => !input.beforeRun.has(artifactName),
    );
    if (newArtifactNames.length === 0) {
        return [];
    }
    const retainedDirectoryPath = path.join(
        input.runDirectoryPath,
        'attachments',
        'fuzz',
    );
    await mkdir(retainedDirectoryPath, { recursive: true });

    return Promise.all(
        newArtifactNames.map(async (artifactName) => {
            const sourcePath = path.join(
                input.artifactDirectoryPath,
                artifactName,
            );
            const retainedPath = path.join(retainedDirectoryPath, artifactName);
            await copyFile(sourcePath, retainedPath);
            const [contents, statistics] = await Promise.all([
                readFile(retainedPath),
                stat(retainedPath),
            ]);

            return {
                path: retainedPath,
                reproduceCommand:
                    `cargo +${foundationParserFuzzToolchain.rustToolchain} fuzz run ` +
                    `foundation-schema-object ${retainedPath}`,
                sha256: createHash('sha256').update(contents).digest('hex'),
                sizeBytes: statistics.size,
            };
        }),
    );
};

export const parseFuzzDurationSeconds = (
    commandArguments: readonly string[],
): number => {
    const positionalArguments = commandArguments.filter(
        (argument) => argument !== '--' && argument !== undefined,
    );
    if (positionalArguments.length === 0) {
        return defaultDurationSeconds;
    }
    if (
        positionalArguments.length !== 1 ||
        !/^[1-9][0-9]*$/u.test(positionalArguments[0] ?? '')
    ) {
        throw new Error(
            'Foundation parser fuzzing accepts one optional positive duration in seconds.',
        );
    }

    const durationSeconds = Number.parseInt(positionalArguments[0], 10);
    if (!Number.isSafeInteger(durationSeconds)) {
        throw new Error(
            'Foundation parser fuzzing duration must be a positive safe integer.',
        );
    }

    return durationSeconds;
};

export const runFoundationParserFuzzing = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const runLog = await createLocalRunLog({
        commandLineArguments: rawArguments,
        lanes: ['Foundation parser fuzzing'],
        scriptName: 'test:fuzz:foundation-schema-object',
    });
    const startedAtMilliseconds = performance.now();
    let campaignStartedAtMilliseconds: number | undefined;
    let durationSeconds: number | undefined;
    let exitCode: number | undefined;
    let runnerError: unknown;
    let latestProgress: FuzzProgress = {};
    let retainedArtifacts: readonly Readonly<Record<string, unknown>>[] = [];
    let writeEvent: ReturnType<typeof createTestEventWriter> = () => undefined;
    try {
        const workingDirectoryPath = path.resolve(process.cwd(), 'fuzz');
        const artifactDirectoryPath = path.join(
            workingDirectoryPath,
            'artifacts',
            'foundation-schema-object',
        );
        writeEvent = createTestEventWriter({
            eventFilePath: path.join(
                runLog.runDirectoryPath,
                'tests',
                'foundation-schema-object-fuzzing.jsonl',
            ),
            projectLabel: 'foundation-schema-object-fuzzing',
        });
        durationSeconds = parseFuzzDurationSeconds(rawArguments);
        writeEvent('fuzz-preflight-started', {
            cargoFuzzVersion: foundationParserFuzzToolchain.cargoFuzzVersion,
            rustToolchain: foundationParserFuzzToolchain.rustToolchain,
        });
        const preflightStartedAtMilliseconds = performance.now();
        try {
            await verifyFoundationParserFuzzToolchain(
                workingDirectoryPath,
                runLog,
            );
            writeEvent('fuzz-preflight-finished', {
                cargoFuzzVersion:
                    foundationParserFuzzToolchain.cargoFuzzVersion,
                durationMilliseconds: Math.round(
                    performance.now() - preflightStartedAtMilliseconds,
                ),
                rustToolchain: foundationParserFuzzToolchain.rustToolchain,
            });
        } catch (error) {
            writeEvent('fuzz-preflight-failed', {
                durationMilliseconds: Math.round(
                    performance.now() - preflightStartedAtMilliseconds,
                ),
                error: serializeErrorDiagnostic(error),
            });
            throw error;
        }
        exitCode = await runCommandsInSeries(
            [
                {
                    args: [
                        `+${foundationParserFuzzToolchain.rustToolchain}`,
                        'metadata',
                        '--locked',
                        '--format-version',
                        '1',
                        '--no-deps',
                    ],
                    command: 'cargo',
                    description: 'verify locked foundation fuzz metadata',
                    env: { ...process.env, RUST_BACKTRACE: 'full' },
                    logFileSlug: 'cargo-metadata-foundation-fuzz',
                    workingDirectoryPath,
                },
            ],
            { outputMode: 'inherit', runLog },
        );
        if (exitCode !== 0) {
            process.exitCode = exitCode;
            return;
        }
        const artifactsBeforeRun = await listFuzzArtifacts(
            artifactDirectoryPath,
        );
        campaignStartedAtMilliseconds = performance.now();
        writeEvent('fuzz-campaign-started', {
            artifactDirectoryPath,
            durationLimitSeconds: durationSeconds,
            reproductionCommandTemplate:
                `cargo +${foundationParserFuzzToolchain.rustToolchain} fuzz run ` +
                'foundation-schema-object <artifact-path>',
            target: 'foundation-schema-object',
        });
        exitCode = await runCommandsInSeries(
            [
                {
                    args: [
                        `+${foundationParserFuzzToolchain.rustToolchain}`,
                        'fuzz',
                        'run',
                        'foundation-schema-object',
                        '--',
                        `-max_total_time=${durationSeconds}`,
                    ],
                    command: 'cargo',
                    description: `fuzz foundation schema object for ${durationSeconds} seconds`,
                    env: { ...process.env, RUST_BACKTRACE: 'full' },
                    logFileSlug: 'cargo-fuzz-foundation-schema-object',
                    workingDirectoryPath,
                },
            ],
            {
                observer: createFuzzProgressObserver({
                    onProgress: (progress) => {
                        latestProgress = progress;
                        writeEvent('fuzz-progress', progress);
                    },
                }),
                outputMode: 'inherit',
                runLog,
            },
        );
        retainedArtifacts = await retainNewFuzzArtifacts({
            artifactDirectoryPath,
            beforeRun: artifactsBeforeRun,
            runDirectoryPath: runLog.runDirectoryPath,
        });
        const campaignDurationMilliseconds = Math.round(
            performance.now() - campaignStartedAtMilliseconds,
        );
        writeEvent('fuzz-campaign-finished', {
            campaignDurationMilliseconds,
            exitCode,
            ...latestProgress,
            retainedArtifacts,
        });
        process.exitCode = exitCode;
    } catch (error) {
        runnerError = error;
        process.exitCode = 1;
        writeEvent('fuzz-runner-failed', {
            error: serializeErrorDiagnostic(error),
        });
        throw error;
    } finally {
        await runLog.finish({
            details: {
                campaignDurationMilliseconds:
                    campaignStartedAtMilliseconds === undefined
                        ? undefined
                        : Math.round(
                              performance.now() - campaignStartedAtMilliseconds,
                          ),
                runnerDurationMilliseconds: Math.round(
                    performance.now() - startedAtMilliseconds,
                ),
                durationSeconds,
                latestProgress,
                retainedArtifacts,
            },
            ...(runnerError === undefined ? {} : { error: runnerError }),
            exitCode: exitCode ?? currentProcessExitCode(),
        });
    }
};

if (import.meta.main) {
    void runFoundationParserFuzzing();
}
