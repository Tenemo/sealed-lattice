import assert from 'node:assert/strict';
import { availableParallelism, freemem } from 'node:os';
import path from 'node:path';

import type { ParticipantRequest } from '#packages/sdk/src/participant/participant-contract.js';
import { type ChromeParticipant } from '#tools/ci/chrome-session.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';
import { selectParticipantBrowserOptions } from '#tools/ci/participant-browser-options.js';
import { createBrowserPool } from '#tools/ci/participant-browser-pool.js';
import { type Relay } from '#tools/ci/participant-browser-relay.js';
import { emptyParticipantTransfer } from '#tools/ci/participant-transfer.js';
import type {
    ParticipantBootstrapMeasurement,
    ParticipantOperationMeasurement,
} from '#tools/ci/participant-workflow-measurements.js';

export type ParticipantOperation = ParticipantRequest['operation'];

// The selected options and the values the whole run derives from them.
export const participantBrowserSettings = (
    options: ReturnType<typeof selectParticipantBrowserOptions>,
) => {
    const { recovery: measureRecovery, ...selected } = options;
    const { participantCount, mode, scalar } = selected;
    const noResult = mode !== 'result';
    const root = path.resolve('.');
    // A registrant that the organizer leaves out of the roster has the origin
    // after the roster participants'. In a rosters run the second roster's
    // registrants take the origins from there on instead.
    const leftOut = participantCount;
    const originCount =
        mode === 'rosters' ? 2 * participantCount - 1 : leftOut + 1;
    // Each browser's page starts a helper per spare processor, up to eight,
    // beside the operation's worker, so the host runs as many browsers at once
    // as it has processors for all of their workers, and no operation's work
    // waits for another's.
    const browserProcessors = scalar ? 1 : Math.min(availableParallelism(), 9);
    return {
        ...selected,
        measureRecovery,
        noResult,
        root,
        leftOut,
        originCount,
        browserProcessors,
    };
};

export type ParticipantBrowserSettings = ReturnType<
    typeof participantBrowserSettings
>;

// The copy of the corrupt organizer's private state that proposes the second
// roster, which reaches that roster's records under its own path of the
// organizer's origin.
export const secondRosterCopy = 'second-roster';

// The host guard for each participant's Chrome process tree.
export const participantMemoryLimit = 3_221_225_472;

// The WebAssembly pages each memory of a pressured browser may hold, fewer
// than a contribution's worker needs.
export const pressurePages = 2048;

// The functions each operation's CPU profile summary ranks.
export const cpuProfileEntries = 60;

export const operationMilliseconds = 3_600_000;

export const requireScalarMemory = (
    details: Readonly<Record<string, unknown>>,
) => {
    assert.ok(
        details.memory !== undefined,
        'The scalar operation reported no memory.',
    );
    for (const memory of [details.memory, details.evaluationMemory]) {
        if (memory === undefined) continue;
        assert.ok(
            memory !== null &&
                typeof memory === 'object' &&
                'helpers' in memory &&
                'helperBytes' in memory &&
                'arenaBytes' in memory,
            'The scalar operation reported incomplete memory.',
        );
        assert.equal(memory.helpers, 0);
        assert.equal(memory.helperBytes, 0);
        assert.equal(memory.arenaBytes, 0);
    }
};

// A page script that runs an asynchronous body against one of the page's
// IndexedDB databases and then closes it. The body sees the open `database`
// and the `result` and `completion` helpers, which settle a request and a
// transaction, so a throw anywhere in it rejects the evaluation instead of
// leaving it waiting.
export const databaseScript = (name: string, body: string) => `(async () => {
    const database = await new Promise((resolve, reject) => {
        const opening = indexedDB.open(${JSON.stringify(name)});
        opening.onerror = () => reject(opening.error);
        opening.onsuccess = () => resolve(opening.result);
    });
    const result = (request) => new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
    const completion = (transaction) => new Promise((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onabort = () => reject(transaction.error ?? new Error('The transaction aborted.'));
    });
    try {
${body}
    } finally {
        database.close();
    }
})()`;

// A roster member: its origin, or a copy of the organizer's private state
// at that origin.
export type Member = Readonly<{ origin: number; copy?: string }>;

// What the run's cleanup releases and records, whichever step the run
// reached.
type CohortCleanup = {
    relay?: Relay;
    sampling: boolean;
    monitor?: Promise<void>;
    allocationMonitor?: Promise<void>;
    finishAllocation?: () => Promise<void>;
    // Failed runs retain their original profiles; a completed run deletes
    // its test profiles.
    profiles?: string;
    guardFailure?: Error;
    completed: boolean;
};

// The browsers, measurements and resources of one run.
export const createCohortState = (
    settings: ParticipantBrowserSettings,
    log: ActiveLocalRunLog,
) => {
    const {
        participantCount,
        mode,
        setupDeparture,
        unselectedCheckpoint,
        memoryPressure,
        publicationFaults,
        sequential,
        departures,
        originCount,
        browserProcessors,
    } = settings;
    // Each browser runs a participant or a copy of a participant's
    // private state, at that participant's origin.
    const browserDetails = new Map<
        string,
        Readonly<{ position: number; copy?: string }>
    >();
    const browsers = createBrowserPool<ChromeParticipant>({
        browsers: sequential
            ? 1
            : Math.floor(availableParallelism() / browserProcessors),
        guardBytes: participantMemoryLimit,
        freeMemory: freemem,
        onEndedForRoom: (key) => {
            log.writeEvent({
                eventType: 'participant-browser-ended-for-room',
                details: browserDetails.get(key),
            });
        },
    });
    // Copies of a participant's private state by name, each with its own
    // Chrome profile at that participant's origin: the equivocator's, and
    // an honest participant's whose records are then lost.
    const copies = new Map<string, number>();
    // The participants whose next browser caps its WebAssembly memories,
    // and the operations that ran under that cap.
    const pressured = new Set<number>();
    const memoryPressures: Readonly<{
        position: number;
        operation: ParticipantOperation;
        pages: number;
        before: number;
        generation: number;
        detail: string;
    }>[] = [];
    const cleanup: CohortCleanup = { sampling: true, completed: false };
    const ordinaryOperations: ParticipantOperationMeasurement[] = [];
    const ordinaryBootstraps: ParticipantBootstrapMeasurement[] = [];
    const measureWorkflow =
        mode === 'plain' &&
        !memoryPressure &&
        !setupDeparture &&
        !unselectedCheckpoint &&
        !publicationFaults &&
        !departures;
    const measuredStages = Array.from({ length: participantCount }, () => [0]);
    const browserSessions = new WeakMap<ChromeParticipant, number>();
    // The backing store histograms each browser last logged.
    const loggedOpenings = new WeakMap<ChromeParticipant, string>();
    const transfers = Array.from(
        { length: originCount },
        emptyParticipantTransfer,
    );
    return {
        browserDetails,
        browsers,
        copies,
        pressured,
        memoryPressures,
        cleanup,
        ordinaryOperations,
        ordinaryBootstraps,
        measureWorkflow,
        measuredStages,
        browserSessions,
        loggedOpenings,
        transfers,
    };
};

export type CohortState = ReturnType<typeof createCohortState>;

export type InParticipantBrowser = <Result>(
    position: number,
    copy: string | undefined,
    action: (chrome: ChromeParticipant) => Promise<Result>,
) => Promise<Result>;
