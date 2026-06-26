import {
    fallbackTerminalWidth,
    isUsableDuration,
    minimumTerminalWidth,
    type CheckProgressMetric,
    type CheckProgressStatus,
    type CheckProgressUnit,
    type CommandState,
    type LaneState,
    type TerminalWriter,
} from './types.js';

export const checkCommandTimingKey = (
    laneName: string,
    commandDescription: string,
): string => `${laneName}\u0000${commandDescription}`;

export const formatProgressDuration = (
    durationMilliseconds: number,
): string => {
    const durationSeconds = durationMilliseconds / 1000;
    if (durationSeconds < 60) {
        return `${durationSeconds.toFixed(1)}s`;
    }

    const wholeSeconds = Math.round(durationSeconds);
    const minutes = Math.floor(wholeSeconds / 60);
    const seconds = wholeSeconds % 60;

    return `${minutes}m${String(seconds).padStart(2, '0')}s`;
};

export const laneStatusText: Readonly<Record<CheckProgressStatus, string>> = {
    failed: 'fail',
    passed: 'pass',
    running: 'run',
    stopped: 'stop',
    waiting: 'wait',
};

export const commandIsFinished = (command: CommandState): boolean =>
    command.status === 'failed' || command.status === 'passed';

const commandProgressForLane = (lane: LaneState): CheckProgressMetric => ({
    completed: lane.commands.filter(commandIsFinished).length,
    total: lane.commands.length,
    unit: 'command',
});

const primaryProgressForLane = (
    lane: LaneState,
): CheckProgressMetric | undefined => {
    if (
        lane.progressSource === 'commands' ||
        lane.progressSource === 'libtest'
    ) {
        return commandProgressForLane(lane);
    }

    return lane.primaryProgress;
};

export const laneElapsedMilliseconds = (
    lane: LaneState,
    nowMilliseconds: number,
): number => {
    if (lane.durationMilliseconds !== undefined) {
        return lane.durationMilliseconds;
    }
    if (lane.startedAtMilliseconds === undefined) {
        return 0;
    }

    return Math.max(0, nowMilliseconds - lane.startedAtMilliseconds);
};

export const truncateLine = (line: string, maximumLength: number): string => {
    if (line.length <= maximumLength) {
        return line;
    }
    if (maximumLength <= 3) {
        return line.slice(0, maximumLength);
    }

    return `${line.slice(0, maximumLength - 3)}...`;
};

const progressUnitLabel = (unit: CheckProgressUnit, count: number): string => {
    switch (unit) {
        case 'command':
            return count === 1 ? 'command' : 'commands';
        case 'task':
            return count === 1 ? 'task' : 'tasks';
        case 'task seen':
            return count === 1 ? 'task seen' : 'tasks seen';
        case 'test':
            return count === 1 ? 'test' : 'tests';
        case 'test file':
            return count === 1 ? 'test file' : 'test files';
    }
};

const formatProgressMetric = (metric: CheckProgressMetric): string => {
    if (metric.total !== undefined) {
        return `${metric.completed}/${metric.total} ${progressUnitLabel(
            metric.unit,
            metric.total,
        )}`;
    }

    return `${metric.completed} ${progressUnitLabel(
        metric.unit,
        metric.completed,
    )}`;
};

export const formatLaneProgress = (lane: LaneState): string => {
    const primary = primaryProgressForLane(lane);
    const secondary = lane.secondaryProgress;
    if (lane.progressSource === 'vitest') {
        return secondary === undefined ? '' : formatProgressMetric(secondary);
    }
    if (lane.progressSource === 'libtest' && secondary !== undefined) {
        return formatProgressMetric(secondary);
    }
    if (primary === undefined) {
        return '';
    }
    if (secondary === undefined) {
        return formatProgressMetric(primary);
    }

    return `${formatProgressMetric(primary)}, ${formatProgressMetric(
        secondary,
    )}`;
};

export const readProgressCount = (value: unknown): number | undefined =>
    isUsableDuration(value) ? Math.trunc(value) : undefined;

const readPositiveIntegerEnvironment = (
    environmentVariableName: string,
): number | undefined => {
    const value = process.env[environmentVariableName];
    if (value === undefined) {
        return undefined;
    }

    const parsedValue = Number.parseInt(value, 10);

    return Number.isFinite(parsedValue) && parsedValue > 0
        ? parsedValue
        : undefined;
};

export const terminalColumnCount = (output: TerminalWriter): number =>
    Math.max(
        output.columns ??
            readPositiveIntegerEnvironment('COLUMNS') ??
            fallbackTerminalWidth,
        minimumTerminalWidth,
    );

export const terminalRowCount = (output: TerminalWriter): number | undefined =>
    output.rows ?? readPositiveIntegerEnvironment('LINES');
