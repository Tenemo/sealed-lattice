import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { checkCommandTimingKey } from './formatting.js';
import {
    isRecord,
    isUsableDuration,
    previousTimingDetailsVersion,
    type CheckCommandStatus,
    type CheckProgressHistoryMetric,
    type CheckProgressMetric,
    type CheckProgressStatus,
    type CheckProgressUnit,
    type CheckRunCommandTiming,
    type CheckRunLaneTiming,
    type CheckRunTimingDetails,
    type CheckTimingHistory,
} from './types.js';

const emptyTimingHistory = (): CheckTimingHistory => ({
    commandDurationMilliseconds: new Map(),
    laneProgress: new Map(),
    laneDurationMilliseconds: new Map(),
});

export { emptyTimingHistory };

export const cloneProgressMetric = (
    metric: CheckProgressMetric | undefined,
): CheckProgressMetric | undefined =>
    metric === undefined
        ? undefined
        : {
              completed: metric.completed,
              total: metric.total,
              unit: metric.unit,
          };

const isProgressUnit = (value: unknown): value is CheckProgressUnit =>
    value === 'command' ||
    value === 'task' ||
    value === 'task seen' ||
    value === 'test' ||
    value === 'test file';

const readProgressMetric = (
    value: unknown,
): CheckProgressMetric | undefined => {
    if (!isRecord(value) || !isUsableDuration(value.completed)) {
        return undefined;
    }
    if (!isProgressUnit(value.unit)) {
        return undefined;
    }

    return {
        completed: value.completed,
        total: isUsableDuration(value.total) ? value.total : undefined,
        unit: value.unit,
    };
};

const readProgressHistoryMetric = (
    value: unknown,
): CheckProgressHistoryMetric | undefined => {
    if (!isRecord(value)) {
        return undefined;
    }
    const primary = readProgressMetric(value.primary);
    const secondary = readProgressMetric(value.secondary);
    if (primary === undefined && secondary === undefined) {
        return undefined;
    }

    return {
        primary,
        secondary,
    };
};

const readCheckRunDetails = (
    value: unknown,
): CheckRunTimingDetails | undefined => {
    if (
        !isRecord(value) ||
        value.objectVersion !== previousTimingDetailsVersion ||
        !Array.isArray(value.lanes)
    ) {
        return undefined;
    }

    const lanes: CheckRunLaneTiming[] = [];
    for (const laneValue of value.lanes) {
        if (
            !isRecord(laneValue) ||
            typeof laneValue.name !== 'string' ||
            !Array.isArray(laneValue.commands)
        ) {
            return undefined;
        }

        const commands: CheckRunCommandTiming[] = [];
        for (const commandValue of laneValue.commands) {
            if (
                !isRecord(commandValue) ||
                typeof commandValue.description !== 'string'
            ) {
                return undefined;
            }
            commands.push({
                description: commandValue.description,
                durationMilliseconds: isUsableDuration(
                    commandValue.durationMilliseconds,
                )
                    ? commandValue.durationMilliseconds
                    : undefined,
                exitCode:
                    typeof commandValue.exitCode === 'number'
                        ? commandValue.exitCode
                        : undefined,
                logPath:
                    typeof commandValue.logPath === 'string'
                        ? commandValue.logPath
                        : undefined,
                status:
                    typeof commandValue.status === 'string'
                        ? (commandValue.status as CheckCommandStatus)
                        : 'waiting',
            });
        }

        lanes.push({
            commands,
            durationMilliseconds: isUsableDuration(
                laneValue.durationMilliseconds,
            )
                ? laneValue.durationMilliseconds
                : undefined,
            name: laneValue.name,
            progress: readProgressHistoryMetric(laneValue.progress),
            status:
                typeof laneValue.status === 'string'
                    ? (laneValue.status as CheckProgressStatus)
                    : 'waiting',
        });
    }

    return {
        completedCommandCount: isUsableDuration(value.completedCommandCount)
            ? value.completedCommandCount
            : 0,
        lanes,
        objectVersion: previousTimingDetailsVersion,
        totalCommandCount: isUsableDuration(value.totalCommandCount)
            ? value.totalCommandCount
            : 0,
    };
};

export const extractCheckTimingHistoryFromSummary = (
    summary: unknown,
): CheckTimingHistory | undefined => {
    if (!isRecord(summary)) {
        return undefined;
    }
    if (summary.scriptName !== 'check' || summary.exitCode !== 0) {
        return undefined;
    }

    const totalDurationMilliseconds = isUsableDuration(
        summary.durationMilliseconds,
    )
        ? summary.durationMilliseconds
        : undefined;
    const details = readCheckRunDetails(summary.details);
    const laneDurationMilliseconds = new Map<string, number>();
    const commandDurationMilliseconds = new Map<string, number>();
    const laneProgress = new Map<string, CheckProgressHistoryMetric>();

    if (details !== undefined) {
        for (const lane of details.lanes) {
            if (isUsableDuration(lane.durationMilliseconds)) {
                laneDurationMilliseconds.set(
                    lane.name,
                    lane.durationMilliseconds,
                );
            }
            if (lane.progress !== undefined) {
                laneProgress.set(lane.name, lane.progress);
            }
            for (const command of lane.commands) {
                if (isUsableDuration(command.durationMilliseconds)) {
                    commandDurationMilliseconds.set(
                        checkCommandTimingKey(lane.name, command.description),
                        command.durationMilliseconds,
                    );
                }
            }
        }
    }

    return {
        commandDurationMilliseconds,
        laneProgress,
        laneDurationMilliseconds,
        totalDurationMilliseconds,
    };
};

export const readPreviousCheckTimingHistory = async (
    logRootDirectoryPath = path.join(process.cwd(), 'logs'),
): Promise<CheckTimingHistory> => {
    const runIndexPath = path.join(logRootDirectoryPath, 'runs.jsonl');
    let runIndexText: string;
    try {
        runIndexText = await readFile(runIndexPath, 'utf8');
    } catch (error) {
        if (isRecord(error) && 'code' in error && error.code === 'ENOENT') {
            return emptyTimingHistory();
        }
        throw error;
    }

    const runIndexLines = runIndexText
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
    let mergedTimingHistory:
        | {
              commandDurationMilliseconds: Map<string, number>;
              laneDurationMilliseconds: Map<string, number>;
              laneProgress: Map<string, CheckProgressHistoryMetric>;
              totalDurationMilliseconds?: number;
          }
        | undefined;
    for (const runIndexLine of [...runIndexLines].reverse()) {
        try {
            const timingHistory = extractCheckTimingHistoryFromSummary(
                JSON.parse(runIndexLine) as unknown,
            );
            if (timingHistory !== undefined) {
                if (mergedTimingHistory === undefined) {
                    mergedTimingHistory = {
                        commandDurationMilliseconds: new Map(
                            timingHistory.commandDurationMilliseconds,
                        ),
                        laneDurationMilliseconds: new Map(
                            timingHistory.laneDurationMilliseconds,
                        ),
                        laneProgress: new Map(timingHistory.laneProgress),
                        totalDurationMilliseconds:
                            timingHistory.totalDurationMilliseconds,
                    };
                } else {
                    for (const [
                        laneName,
                        progress,
                    ] of timingHistory.laneProgress) {
                        if (!mergedTimingHistory.laneProgress.has(laneName)) {
                            mergedTimingHistory.laneProgress.set(
                                laneName,
                                progress,
                            );
                        }
                    }
                }
            }
        } catch {
            // Ignore corrupt local history lines. They are diagnostics only.
        }
    }

    return mergedTimingHistory ?? emptyTimingHistory();
};
