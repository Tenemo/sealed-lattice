import path from 'node:path';

import { createLocalRunLog, currentProcessExitCode } from './local-run-log.js';
import { runCommandsInSeries } from './run-command.js';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

const defaultDurationSeconds = 60;

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

    return Number.parseInt(positionalArguments[0], 10);
};

export const runFoundationParserFuzzing = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const durationSeconds = parseFuzzDurationSeconds(rawArguments);
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
                        '+nightly',
                        'fuzz',
                        'run',
                        'foundation-schema-object',
                        '--',
                        `-max_total_time=${durationSeconds}`,
                    ],
                    command: 'cargo',
                    description: `fuzz foundation schema object for ${durationSeconds} seconds`,
                    logFileSlug: 'cargo-fuzz-foundation-schema-object',
                    workingDirectoryPath: path.resolve(process.cwd(), 'fuzz'),
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
