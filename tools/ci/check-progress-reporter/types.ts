import type { Writable } from 'node:stream';

import type { OutputLineBuffer, RecentOutputBuffer } from './output-buffers.js';

export const previousTimingDetailsVersion =
    'sealed-lattice-check-run-details-v1';
export const latestOutputLineLimit = 6;
export const failureOutputLineLimit = 40;
export const defaultRenderIntervalMilliseconds = 100;
export const renderDebounceMilliseconds = 25;
export const fallbackTerminalWidth = 80;
export const minimumTerminalWidth = 40;
export const progressEventPrefix = 'sealed-lattice-progress ';

export type CheckProgressStatus =
    | 'failed'
    | 'passed'
    | 'running'
    | 'stopped'
    | 'waiting';

export type CheckCommandStatus = CheckProgressStatus;

export type CheckProgressSource =
    | 'commands'
    | 'libtest'
    | 'opaque'
    | 'turbo'
    | 'vitest';
export type CheckProgressUnit =
    | 'command'
    | 'task'
    | 'task seen'
    | 'test'
    | 'test file';

export type CheckProgressMetric = {
    completed: number;
    total?: number;
    unit: CheckProgressUnit;
};

export const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

export const isUsableDuration = (value: unknown): value is number =>
    typeof value === 'number' && Number.isFinite(value) && value >= 0;

export type CheckProgressCommandPlan = {
    readonly description: string;
    readonly expectedDurationMilliseconds?: number;
};

export type CheckProgressLanePlan = {
    readonly commands: readonly CheckProgressCommandPlan[];
    readonly expectedDurationMilliseconds?: number;
    readonly name: string;
    readonly progress?: {
        readonly primary?: CheckProgressMetric;
        readonly secondary?: CheckProgressMetric;
        readonly source: CheckProgressSource;
    };
};

export type CheckProgressHistoryMetric = {
    readonly primary?: CheckProgressMetric;
    readonly secondary?: CheckProgressMetric;
};

export type CheckTimingHistory = {
    readonly commandDurationMilliseconds: ReadonlyMap<string, number>;
    readonly laneProgress: ReadonlyMap<string, CheckProgressHistoryMetric>;
    readonly laneDurationMilliseconds: ReadonlyMap<string, number>;
    readonly totalDurationMilliseconds?: number;
};

export type CheckRunCommandTiming = {
    readonly description: string;
    readonly durationMilliseconds?: number;
    readonly exitCode?: number;
    readonly logPath?: string;
    readonly status: CheckCommandStatus;
};

export type CheckRunLaneTiming = {
    readonly commands: readonly CheckRunCommandTiming[];
    readonly durationMilliseconds?: number;
    readonly name: string;
    readonly progress?: CheckProgressHistoryMetric;
    readonly status: CheckProgressStatus;
};

export type CheckRunTimingDetails = {
    readonly completedCommandCount: number;
    readonly lanes: readonly CheckRunLaneTiming[];
    readonly objectVersion: 'sealed-lattice-check-run-details-v1';
    readonly totalCommandCount: number;
};

export type CommandState = {
    description: string;
    durationMilliseconds?: number;
    exitCode?: number;
    expectedDurationMilliseconds?: number;
    outputLineBuffer: OutputLineBuffer;
    logPath?: string;
    recentOutput: RecentOutputBuffer;
    startedAtMilliseconds?: number;
    status: CheckCommandStatus;
};

export type LaneState = {
    commands: CommandState[];
    durationMilliseconds?: number;
    expectedDurationMilliseconds?: number;
    finishedAtMilliseconds?: number;
    name: string;
    primaryProgress?: CheckProgressMetric;
    progressSource: CheckProgressSource;
    secondaryProgress?: CheckProgressMetric;
    startedAtMilliseconds?: number;
    status: CheckProgressStatus;
    libtestCompletedTestCount: number;
    libtestCompletedTestCountBeforeCurrentBatch: number;
    libtestDiscoveredTestCount: number;
    libtestObservedCompactTestCountInCurrentBatch: number;
    libtestRunningTestCount?: number;
    turboTaskIdsSeen: Set<string>;
};

export type CheckFailureDetail = {
    readonly commandDescription?: string;
    readonly exitCode?: number;
    readonly laneName: string;
    readonly logPath?: string;
    readonly recentOutputLines: readonly string[];
};

export type TerminalWriter = Pick<Writable, 'write'> & {
    readonly columns?: number;
    readonly isTTY?: boolean;
    readonly rows?: number;
};
