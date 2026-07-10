import { parseLibtestResultSummary } from './libtest-output.js';
import type {
    CommandOutputStreamName,
    CommandRunObserver,
} from './run-command.js';

type FocusedRustTestMatchTracker = {
    readonly matchedTestCount: () => number;
    readonly observer: CommandRunObserver;
};

type FocusedRustTestRunResult = {
    readonly exitCode: number;
    readonly failureMessage?: string;
};

export const createFocusedRustTestMatchTracker =
    (): FocusedRustTestMatchTracker => {
        const lineBuffers: Record<CommandOutputStreamName, string> = {
            stderr: '',
            stdout: '',
        };
        let matchedTestCount = 0;

        const consumeLine = (line: string): void => {
            const summary = parseLibtestResultSummary(line);
            if (summary === undefined) {
                return;
            }

            matchedTestCount +=
                summary.passedTestCount +
                summary.failedTestCount +
                summary.ignoredTestCount +
                summary.measuredTestCount;
        };

        const consumeCompleteLines = (
            streamName: CommandOutputStreamName,
        ): void => {
            let newlineIndex = lineBuffers[streamName].indexOf('\n');
            while (newlineIndex !== -1) {
                const line = lineBuffers[streamName]
                    .slice(0, newlineIndex)
                    .replace(/\r$/u, '');
                lineBuffers[streamName] = lineBuffers[streamName].slice(
                    newlineIndex + 1,
                );
                consumeLine(line);
                newlineIndex = lineBuffers[streamName].indexOf('\n');
            }
        };

        const flushRemainingLines = (): void => {
            for (const streamName of ['stderr', 'stdout'] as const) {
                if (lineBuffers[streamName].length > 0) {
                    consumeLine(lineBuffers[streamName]);
                    lineBuffers[streamName] = '';
                }
            }
        };

        return {
            matchedTestCount: () => matchedTestCount,
            observer: {
                onCommandStart: (): void => {
                    lineBuffers.stderr = '';
                    lineBuffers.stdout = '';
                    matchedTestCount = 0;
                },
                onCommandOutput: (event): void => {
                    lineBuffers[event.streamName] += event.chunk;
                    consumeCompleteLines(event.streamName);
                },
                onCommandExit: (): void => {
                    flushRemainingLines();
                },
            },
        };
    };

export const resolveFocusedRustTestRunResult = (input: {
    readonly commandExitCode: number;
    readonly matchedTestCount: number;
    readonly runnerName: string;
    readonly testFilter: string;
}): FocusedRustTestRunResult => {
    if (input.commandExitCode !== 0 || input.matchedTestCount > 0) {
        return { exitCode: input.commandExitCode };
    }

    return {
        exitCode: 1,
        failureMessage: `${input.runnerName} filter "${input.testFilter}" matched zero tests.`,
    };
};
