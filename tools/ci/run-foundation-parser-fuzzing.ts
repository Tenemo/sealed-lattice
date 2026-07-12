import { spawnSync } from 'node:child_process';
import path from 'node:path';

import { createLocalRunLog, currentProcessExitCode } from './local-run-log.js';
import { runCommandsInSeries } from './run-command.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const defaultDurationSeconds = 60;
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

const verifyFoundationParserFuzzToolchain = (
    workingDirectoryPath: string,
): void => {
    const result = spawnSync(
        'cargo',
        [
            `+${foundationParserFuzzToolchain.rustToolchain}`,
            'fuzz',
            '--version',
        ],
        {
            cwd: workingDirectoryPath,
            encoding: 'utf8',
            env: process.env,
        },
    );
    if (result.error !== undefined) {
        throw result.error;
    }
    if (result.status !== 0) {
        throw new Error(
            `Foundation parser fuzzing requires Rust ${foundationParserFuzzToolchain.rustToolchain} and cargo-fuzz ${foundationParserFuzzToolchain.cargoFuzzVersion}; install them explicitly before running this manual lane. ${result.stderr.trim()}`,
        );
    }
    requireExpectedCargoFuzzVersion(result.stdout);
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
    const durationSeconds = parseFuzzDurationSeconds(rawArguments);
    const workingDirectoryPath = path.resolve(process.cwd(), 'fuzz');
    verifyFoundationParserFuzzToolchain(workingDirectoryPath);
    const runLog = await createLocalRunLog({
        commandLineArguments: rawArguments,
        lanes: ['Foundation parser fuzzing'],
        scriptName: 'test:fuzz:foundation-schema-object',
    });
    let exitCode: number | undefined;
    try {
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
                    logFileSlug: 'cargo-metadata-foundation-fuzz',
                    workingDirectoryPath,
                },
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
                    logFileSlug: 'cargo-fuzz-foundation-schema-object',
                    workingDirectoryPath,
                },
            ],
            { outputMode: 'inherit', runLog },
        );
        process.exitCode = exitCode;
    } finally {
        await runLog.finish({
            details: { durationSeconds },
            exitCode: exitCode ?? currentProcessExitCode(),
        });
    }
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void runFoundationParserFuzzing();
}
