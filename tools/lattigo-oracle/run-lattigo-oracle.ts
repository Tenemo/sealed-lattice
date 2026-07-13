// Docker-backed Lattigo cross-check of the canonical BGV-RNS fixtures.
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import {
    createLocalRunLog,
    currentProcessExitCode,
    type ActiveLocalRunLog,
} from '../ci/local-run-log.js';
import {
    runCommandAndCaptureOutput,
    runCommandsInSeries,
    type CapturedCommandResult,
} from '../ci/run-command.js';
import { serializeErrorDiagnostic } from '../ci/run-log-diagnostics.js';
import { createTestEventWriter } from '../ci/test-event-journal.js';

export const lattigoOracleDirectoryPath = fileURLToPath(
    new URL('./', import.meta.url),
);
const oracleImageName = 'sealed-lattice-lattigo-oracle:bgv-rns';

export const buildLattigoOracleDockerBuildArguments = (): readonly string[] => [
    'build',
    '-f',
    'Dockerfile',
    '-t',
    oracleImageName,
    '.',
];

export const buildLattigoOracleDockerRunArguments = (
    containerName = 'sealed-lattice-lattigo-oracle-manual',
): readonly string[] => [
    'run',
    '--name',
    containerName,
    '--network',
    'none',
    '--read-only',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--pids-limit',
    '128',
    '--memory',
    '2g',
    '--memory-swap',
    '2g',
    oracleImageName,
];

type DockerCaptureResult = CapturedCommandResult & {
    readonly durationMilliseconds: number;
};

const captureDockerCommand = async (
    commandArguments: readonly string[],
    runLog: ActiveLocalRunLog,
): Promise<DockerCaptureResult> => {
    const startedAtMilliseconds = performance.now();
    const result = await runCommandAndCaptureOutput(
        {
            args: commandArguments,
            command: 'docker',
            description: `docker ${commandArguments.join(' ')}`,
            logFileSlug: `docker-${commandArguments[0] ?? 'command'}`,
            workingDirectoryPath: lattigoOracleDirectoryPath,
        },
        { runLog },
    );
    const capturedResult: DockerCaptureResult = {
        ...result,
        durationMilliseconds: Math.round(
            performance.now() - startedAtMilliseconds,
        ),
    };
    runLog.writeEvent({
        details: {
            arguments: commandArguments,
            durationMilliseconds: capturedResult.durationMilliseconds,
            processStatus: capturedResult.processStatus,
            terminationSignal: capturedResult.terminationSignal,
        },
        eventType: 'specialist-command-finished',
    });

    return capturedResult;
};

export const requireSuccessfulDockerCapture = (
    result: CapturedCommandResult,
    description: string,
    input: { readonly requireOutput?: boolean } = {},
): string => {
    const output = result.stdout.trim();
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        throw new Error(
            `${description} failed with exit code ${result.exitCode}, signal ${result.terminationSignal ?? 'none'}. ${result.stderr.trim()}`,
        );
    }
    if (input.requireOutput === true && output.length === 0) {
        throw new Error(`${description} returned no output.`);
    }

    return output;
};

export const parseDockerContainerState = (
    rawState: string,
): Readonly<Record<string, unknown>> | undefined => {
    try {
        const parsed = JSON.parse(rawState) as unknown;
        return typeof parsed === 'object' && parsed !== null
            ? (parsed as Readonly<Record<string, unknown>>)
            : undefined;
    } catch {
        return undefined;
    }
};

export const runLattigoOracle = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const runLog = await createLocalRunLog({
        commandLineArguments: rawArguments,
        lanes: ['Lattigo arithmetic oracle'],
        scriptName: 'test:lattigo-oracle',
    });
    const containerName =
        `sealed-lattice-lattigo-oracle-${process.pid}-` +
        `${Date.now().toString(36)}`;
    let containerWasCreated = false;
    let exitCode: number | undefined;
    let runnerError: unknown;
    let diagnostics: Readonly<Record<string, unknown>> = {};
    let writeEvent: ReturnType<typeof createTestEventWriter> = () => undefined;

    try {
        writeEvent = createTestEventWriter({
            eventFilePath: path.join(
                runLog.runDirectoryPath,
                'tests',
                'lattigo-arithmetic-oracle.jsonl',
            ),
            projectLabel: 'lattigo-arithmetic-oracle',
        });
        if (rawArguments.length > 0) {
            throw new Error('The Lattigo oracle does not accept arguments.');
        }
        writeEvent('oracle-image-build-started', { image: oracleImageName });
        exitCode = await runCommandsInSeries(
            [
                {
                    args: buildLattigoOracleDockerBuildArguments(),
                    command: 'docker',
                    description: 'build Lattigo arithmetic oracle image',
                    logFileSlug: 'docker-build-lattigo-oracle',
                    workingDirectoryPath: lattigoOracleDirectoryPath,
                },
            ],
            { outputMode: 'inherit', runLog },
        );
        if (exitCode !== 0) {
            process.exitCode = exitCode;
            return;
        }
        const dockerVersion = await captureDockerCommand(
            ['version', '--format', '{{.Server.Version}}'],
            runLog,
        );
        const dockerServerVersion = requireSuccessfulDockerCapture(
            dockerVersion,
            'Docker server version probe',
            { requireOutput: true },
        );
        const imageIdentity = await captureDockerCommand(
            ['image', 'inspect', '--format', '{{.Id}}', oracleImageName],
            runLog,
        );
        const resolvedImageIdentity = requireSuccessfulDockerCapture(
            imageIdentity,
            'Lattigo oracle image identity probe',
            { requireOutput: true },
        );
        writeEvent('oracle-container-started', {
            containerName,
            dockerServerVersion,
            imageIdentity: resolvedImageIdentity,
        });
        containerWasCreated = true;
        exitCode = await runCommandsInSeries(
            [
                {
                    args: buildLattigoOracleDockerRunArguments(containerName),
                    command: 'docker',
                    description: 'run Lattigo arithmetic oracle container',
                    logFileSlug: 'docker-run-lattigo-oracle',
                    workingDirectoryPath: lattigoOracleDirectoryPath,
                },
            ],
            { outputMode: 'inherit', runLog },
        );

        const inspection = await captureDockerCommand(
            ['inspect', '--format', '{{json .State}}', containerName],
            runLog,
        );
        const rawContainerState = requireSuccessfulDockerCapture(
            inspection,
            'Lattigo oracle container state inspection',
            { requireOutput: true },
        );
        const containerState = parseDockerContainerState(rawContainerState);
        if (containerState === undefined) {
            throw new Error(
                'Lattigo oracle container state inspection returned malformed JSON.',
            );
        }
        diagnostics = {
            containerName,
            containerState,
            dockerVersionProbeDurationMilliseconds:
                dockerVersion.durationMilliseconds,
            dockerServerVersion,
            imageIdentity: resolvedImageIdentity,
            imageIdentityProbeDurationMilliseconds:
                imageIdentity.durationMilliseconds,
            inspectionDurationMilliseconds: inspection.durationMilliseconds,
            inspectProcessStatus: inspection.processStatus,
            inspectSignal: inspection.terminationSignal,
            runExitCode: exitCode,
        };
        writeEvent('oracle-container-finished', diagnostics);
        process.exitCode = exitCode;
    } catch (error) {
        runnerError = error;
        process.exitCode = 1;
        writeEvent('oracle-runner-failed', {
            error: serializeErrorDiagnostic(error),
        });
    } finally {
        if (containerWasCreated) {
            try {
                const removal = await captureDockerCommand(
                    ['rm', '--force', containerName],
                    runLog,
                );
                requireSuccessfulDockerCapture(
                    removal,
                    'Lattigo oracle container cleanup',
                );
                writeEvent('oracle-container-removed', {
                    durationMilliseconds: removal.durationMilliseconds,
                    processStatus: removal.processStatus,
                    signal: removal.terminationSignal,
                });
            } catch (cleanupError) {
                writeEvent('oracle-container-removal-failed', {
                    error: serializeErrorDiagnostic(cleanupError),
                });
                if (runnerError === undefined) {
                    runnerError = cleanupError;
                    process.exitCode = 1;
                }
            }
        }
        await runLog.finish({
            details: diagnostics,
            ...(runnerError === undefined ? {} : { error: runnerError }),
            exitCode: exitCode ?? currentProcessExitCode(),
        });
    }

    if (runnerError !== undefined) {
        throw runnerError instanceof Error
            ? runnerError
            : Object.assign(new Error('The Lattigo oracle runner failed.'), {
                  cause: runnerError,
              });
    }
};

if (import.meta.main) {
    void runLattigoOracle();
}
