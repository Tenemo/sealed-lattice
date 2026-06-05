import type { OutputLineBuffer, RecentOutputBuffer } from './output-buffers.js';
import type {
    CheckCommandStatus,
    CheckProgressMetric,
    CheckProgressSource,
    CheckProgressStatus,
} from './types.js';

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
