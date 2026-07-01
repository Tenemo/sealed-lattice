import {
    parseLibtestFinishedTestLine,
    parseLibtestRunningTestCount,
} from '../libtest-output.js';

import { readProgressCount } from './formatting.js';
import { isRecord, progressEventPrefix, type LaneState } from './types.js';

export const consumeStructuredProgressLine = (
    lane: LaneState,
    line: string,
): void => {
    try {
        const payload = JSON.parse(
            line.slice(progressEventPrefix.length),
        ) as unknown;
        if (!isRecord(payload) || payload.tool !== 'vitest') {
            return;
        }

        const files = isRecord(payload.files) ? payload.files : undefined;
        const tests = isRecord(payload.tests) ? payload.tests : undefined;
        const completedFiles = readProgressCount(files?.completed);
        const totalFiles = readProgressCount(files?.total);
        const completedTests = readProgressCount(tests?.completed);
        const totalTests = readProgressCount(tests?.total);
        if (completedFiles !== undefined) {
            lane.primaryProgress = {
                completed: completedFiles,
                total: totalFiles,
                unit: 'test file',
            };
        }
        if (
            completedTests !== undefined &&
            (completedTests > 0 || (totalTests !== undefined && totalTests > 0))
        ) {
            lane.secondaryProgress = {
                completed: completedTests,
                total: totalTests,
                unit: 'test',
            };
        }
    } catch {
        // Progress markers are diagnostic only; malformed lines should not
        // fail the validation run.
    }
};

export const consumeTurboProgressLine = (
    lane: LaneState,
    line: string,
): void => {
    const runningMatch = /Running build in (\d+) packages/u.exec(line);
    if (runningMatch?.[1] !== undefined) {
        lane.primaryProgress = {
            completed: lane.primaryProgress?.completed ?? 0,
            total: Number(runningMatch[1]),
            unit: 'task seen',
        };

        return;
    }

    const taskSeenMatch = /^([^:\s]+):build:\s+(?:cache hit|cache miss)/u.exec(
        line,
    );
    if (taskSeenMatch?.[1] !== undefined) {
        lane.turboTaskIdsSeen.add(taskSeenMatch[1]);
        lane.primaryProgress = {
            completed: lane.turboTaskIdsSeen.size,
            total: lane.primaryProgress?.total,
            unit: 'task seen',
        };

        return;
    }

    const finalTaskMatch = /Tasks:\s+(\d+)\s+successful,\s+(\d+)\s+total/u.exec(
        line,
    );
    if (finalTaskMatch?.[1] !== undefined && finalTaskMatch[2] !== undefined) {
        lane.primaryProgress = {
            completed: Number(finalTaskMatch[1]),
            total: Number(finalTaskMatch[2]),
            unit: 'task',
        };
    }
};

const refreshLibtestSecondaryProgress = (lane: LaneState): void => {
    const discoveredTestCount =
        lane.libtestDiscoveredTestCount === 0
            ? lane.secondaryProgress?.total
            : lane.libtestDiscoveredTestCount;
    lane.secondaryProgress = {
        completed: lane.libtestCompletedTestCount,
        total: discoveredTestCount,
        unit: 'test',
    };
};

const beginLibtestBatch = (lane: LaneState, runningTestCount: number): void => {
    lane.libtestRunningTestCount = runningTestCount;
    lane.libtestCompletedTestCountBeforeCurrentBatch =
        lane.libtestCompletedTestCount;
    lane.libtestObservedCompactTestCountInCurrentBatch = 0;
    lane.libtestDiscoveredTestCount += runningTestCount;
    refreshLibtestSecondaryProgress(lane);
};

const recordLibtestCompletedTests = (
    lane: LaneState,
    completedTestCount: number,
): void => {
    lane.libtestCompletedTestCount += completedTestCount;
    lane.libtestObservedCompactTestCountInCurrentBatch = Math.max(
        lane.libtestObservedCompactTestCountInCurrentBatch,
        lane.libtestCompletedTestCount -
            lane.libtestCompletedTestCountBeforeCurrentBatch,
    );
    refreshLibtestSecondaryProgress(lane);
};

const recordLibtestCurrentBatchProgress = (
    lane: LaneState,
    completedTestCountInCurrentBatch: number,
    totalTestCountInCurrentBatch?: number,
): void => {
    if (totalTestCountInCurrentBatch !== undefined) {
        if (lane.libtestRunningTestCount === undefined) {
            lane.libtestRunningTestCount = totalTestCountInCurrentBatch;
            lane.libtestCompletedTestCountBeforeCurrentBatch =
                lane.libtestCompletedTestCount;
            lane.libtestDiscoveredTestCount += totalTestCountInCurrentBatch;
        } else if (
            totalTestCountInCurrentBatch > lane.libtestRunningTestCount
        ) {
            lane.libtestDiscoveredTestCount +=
                totalTestCountInCurrentBatch - lane.libtestRunningTestCount;
            lane.libtestRunningTestCount = totalTestCountInCurrentBatch;
        }
    }

    const currentBatchTotal =
        lane.libtestRunningTestCount ?? totalTestCountInCurrentBatch;
    const boundedCompletedTestCount =
        currentBatchTotal === undefined
            ? completedTestCountInCurrentBatch
            : Math.min(completedTestCountInCurrentBatch, currentBatchTotal);
    lane.libtestObservedCompactTestCountInCurrentBatch = Math.max(
        lane.libtestObservedCompactTestCountInCurrentBatch,
        boundedCompletedTestCount,
    );
    lane.libtestCompletedTestCount = Math.max(
        lane.libtestCompletedTestCount,
        lane.libtestCompletedTestCountBeforeCurrentBatch +
            lane.libtestObservedCompactTestCountInCurrentBatch,
    );
    refreshLibtestSecondaryProgress(lane);
};

export const consumeLibtestProgressLine = (
    lane: LaneState,
    line: string,
): string | undefined => {
    const trimmedLine = line.trim();
    const runningTestCount = parseLibtestRunningTestCount(trimmedLine);
    if (runningTestCount !== undefined) {
        beginLibtestBatch(lane, runningTestCount);

        return undefined;
    }

    const compactProgressMatch = /^([.iF]+)\s+(\d+)\/(\d+)$/u.exec(trimmedLine);
    if (
        compactProgressMatch?.[2] !== undefined &&
        compactProgressMatch[3] !== undefined
    ) {
        recordLibtestCurrentBatchProgress(
            lane,
            Number(compactProgressMatch[2]),
            Number(compactProgressMatch[3]),
        );

        return undefined;
    }

    const compactProgressOnlyMatch = /^[.iF]+$/u.exec(trimmedLine);
    if (compactProgressOnlyMatch !== null) {
        recordLibtestCurrentBatchProgress(
            lane,
            lane.libtestObservedCompactTestCountInCurrentBatch +
                trimmedLine.length,
        );

        return undefined;
    }

    const compactProgressPrefixMatch = /^([.iF]+)(test .+)$/u.exec(trimmedLine);
    if (
        compactProgressPrefixMatch?.[1] !== undefined &&
        compactProgressPrefixMatch[2] !== undefined
    ) {
        recordLibtestCurrentBatchProgress(
            lane,
            lane.libtestObservedCompactTestCountInCurrentBatch +
                compactProgressPrefixMatch[1].length,
        );

        return compactProgressPrefixMatch[2];
    }

    if (parseLibtestFinishedTestLine(trimmedLine) !== undefined) {
        recordLibtestCompletedTests(lane, 1);

        return line;
    }

    const finalResultMatch =
        /^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; \d+ filtered out/u.exec(
            trimmedLine,
        );
    if (
        finalResultMatch?.[1] !== undefined &&
        finalResultMatch[2] !== undefined &&
        finalResultMatch[3] !== undefined &&
        finalResultMatch[4] !== undefined
    ) {
        const completedTestCount =
            Number(finalResultMatch[1]) +
            Number(finalResultMatch[2]) +
            Number(finalResultMatch[3]) +
            Number(finalResultMatch[4]);
        recordLibtestCurrentBatchProgress(
            lane,
            completedTestCount,
            lane.libtestRunningTestCount ?? completedTestCount,
        );
    }

    return line;
};
