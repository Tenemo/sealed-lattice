import { readFile } from 'node:fs/promises';
import path from 'node:path';

// The parts of a run directory's files that the renewal audit and the
// phone-time projection read. Each field keeps the name the writing runner
// gives it.
export type RunSummary = Readonly<{
    repositoryCommitHash: string;
    result: string;
}>;

export type RunMetadata = Readonly<{
    commandLineArguments: readonly string[];
    scriptName: string;
}>;

export type RunEvent = Readonly<{
    details?: Readonly<Record<string, unknown>>;
    eventType: string;
}>;

export type ParticipantTransferTotals = Readonly<{
    incompleteExchanges: number;
    receivedPayloadBytes: number;
    sentPayloadBytes: number;
    unknownRequestLengths: number;
}>;

// The details of a `participant-operation` event: the participant's
// cumulative origin counters when the operation ended.
export type ParticipantOperationEvent = Readonly<{
    milliseconds: number;
    operation: string;
    originTransfer: ParticipantTransferTotals;
    position: number;
    result?: Readonly<{ status?: string }>;
}>;

type WorkflowOperation = Readonly<{
    finished: number;
    id: number;
    memory?: Readonly<{ helpers: number }>;
    operation: string;
    outcome: string;
    position: number;
    started: number;
}>;

type WorkflowParticipant = Readonly<{
    activeMillisecondsUpperBound: number;
    combinedWorkerHelperArenaBytes: number;
    maximumVisitUpperBoundMilliseconds: number;
    position: number;
    productiveVisits: number;
    visits: readonly Readonly<{
        activeMillisecondsUpperBound: number;
        operationIds: readonly number[];
        stage: string;
    }>[];
}>;

type Interruption = Readonly<{
    operation: string;
    position: number;
}>;

export type ParticipantRunResult = Readonly<{
    activePositions?: readonly number[];
    crossRosterProbes?: readonly Readonly<{
        detail: unknown;
        family: string;
        origin: number;
        served: number;
    }>[];
    departed?: readonly number[];
    departedAfterOffer?: number;
    departedAfterRoster?: number;
    departedBeforeClose?: number;
    departureSchedule?: readonly Readonly<{
        boundary: string;
        position: number;
    }>[];
    departures?: boolean;
    identifiers?: unknown;
    incompleteResponseEvidence?: unknown;
    independentOutcome?: Readonly<{
        details?: Readonly<{
            identifiers?: unknown;
            memory?: Readonly<{ helpers: number }>;
        }>;
        status: string;
    }>;
    interruptions?: readonly Interruption[];
    mode?: string;
    omittedBallot?: unknown;
    optionCount: number;
    participantCount: number;
    publicationFaultEvidence?: unknown;
    publicationFaults?: boolean;
    publicationRecoveryEvidence?: unknown;
    recovery?: boolean;
    result?: Readonly<{ kind: string }>;
    results?: Readonly<{ first: unknown; second: unknown }>;
    runtimeIdentity: string;
    sampledResources?: readonly Readonly<{ originStorageBytes: number }>[];
    scalar: boolean;
    scope: unknown;
    selectedPositions?: readonly number[];
    selectionFork?: boolean;
    sequential?: boolean;
    setupDeparture?: boolean;
    sourceCustody?: unknown;
    sourceRefusals?: unknown;
    standaloneMilliseconds?: number;
    stateLosses?: readonly unknown[];
    topCount: number;
    transfers: readonly ParticipantTransferTotals[];
    unmeasured?: unknown;
    unselectedCheckpoint?: boolean;
    workflow?: Readonly<{
        activeMillisecondsUpperBound: number;
        operations: readonly WorkflowOperation[];
        participants: readonly WorkflowParticipant[];
        scope: unknown;
        sequentialCompletionMilliseconds: number;
    }>;
}>;

export const readRunJson = async <Value>(
    runDirectoryPath: string,
    file: string,
): Promise<Value> =>
    JSON.parse(
        await readFile(path.join(runDirectoryPath, file), 'utf8'),
    ) as Value;

export const readRunEvents = async (
    runDirectoryPath: string,
): Promise<readonly RunEvent[]> =>
    (await readFile(path.join(runDirectoryPath, 'events.jsonl'), 'utf8'))
        .trim()
        .split(/\r?\n/u)
        .map((line) => JSON.parse(line) as RunEvent);

export const participantOperationEvents = (
    events: readonly RunEvent[],
): readonly ParticipantOperationEvent[] =>
    events
        .filter((event) => event.eventType === 'participant-operation')
        .map((event) => event.details as unknown as ParticipantOperationEvent);
