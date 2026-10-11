import assert from 'node:assert/strict';
import {
    cp,
    mkdir,
    mkdtemp,
    readFile,
    readdir,
    rm,
    writeFile,
} from 'node:fs/promises';
import { availableParallelism, freemem } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { build } from 'tsdown';

import type { ParticipantRequest } from '#packages/sdk/src/participant/participant.js';
import { chunkBytes } from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import type { WorkerResult } from '#packages/sdk/src/participant/worker/runtime/worker-messages.js';
import { compileOperationProofDraws } from '#tests/operation-seed-model.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import { sampleFileAllocation } from '#tools/ci/file-allocation.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';
import {
    scheduleParticipantDepartures,
    selectParticipantBrowserOptions,
} from '#tools/ci/participant-browser-options.js';
import { createBrowserPool } from '#tools/ci/participant-browser-pool.js';
import { loadForeignPoll } from '#tools/ci/participant-browser-public-records.js';
import {
    type Relay,
    type ViewedRecord,
    haltingClient,
    participantDatabase,
    participantNamespace,
    secondRosterPath,
    startRelay,
} from '#tools/ci/participant-browser-relay.js';
import {
    type CpuProfileSummary,
    summarizeCpuTrace,
} from '#tools/ci/participant-cpu-profile.js';
import {
    type PaddingCut,
    type PaddingHaltObservation,
    type PaddingSlotObservation,
    type PreparationCut,
    paddingHaltingClient,
    preparationHaltingClient,
    validatePaddingObservation,
} from '#tools/ci/participant-padding-halt.js';
import type {
    CheckpointCustodyObservation,
    SourceCustodyObservation,
} from '#tools/ci/participant-preparation-storage.js';
import { assembleParticipantRuntime } from '#tools/ci/participant-runtime-assembly.js';
import {
    type ChromeParticipant,
    launchChromeParticipant,
} from '#tools/ci/participant-runtime-chrome.js';
import { emptyParticipantTransfer } from '#tools/ci/participant-transfer.js';
import type {
    ParticipantBootstrapMeasurement,
    ParticipantOperationMeasurement,
} from '#tools/ci/participant-workflow-measurements.js';
import {
    readProtocolProcesses,
    sumProtocolProcessTree,
} from '#tools/ci/process-tree-memory.js';
import { redactDiagnosticText } from '#tools/ci/run-log-diagnostics.js';

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

type ParticipantBrowserSettings = ReturnType<typeof participantBrowserSettings>;

// The copy of the corrupt organizer's private state that proposes the second
// roster, which reaches that roster's records under its own path of the
// organizer's origin.
export const secondRosterCopy = 'second-roster';
// The host guard for each participant's Chrome process tree.
const participantMemoryLimit = 3_221_225_472;
// The WebAssembly pages each memory of a pressured browser may hold, fewer
// than a contribution's worker needs.
const pressurePages = 2048;
// The functions each operation's CPU profile summary ranks.
const cpuProfileEntries = 60;
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

// Lists words as prose.
export const prose = (words: readonly string[]) =>
    words.length < 2
        ? words.join('')
        : `${words.slice(0, -1).join(', ')} or ${words[words.length - 1]}`;

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

type CohortState = ReturnType<typeof createCohortState>;

// Sets up the run, opens its relay and monitors, creates the poll and
// returns what every case uses.
export const openParticipantCohort = async (
    settings: ParticipantBrowserSettings,
    log: ActiveLocalRunLog,
    state: CohortState,
) => {
    const {
        participantCount,
        optionCount,
        mode,
        foreignPoll,
        profiling,
        scalar,
        setupDeparture,
        unselectedCheckpoint,
        selectionFork,
        departures,
        basePort,
        topCount,
        noResult,
        root,
        originCount,
    } = settings;
    const {
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
    } = state;
    let nextBrowserSession = 0;
    let nextMeasuredOperation = 0;
    const {
        maximumCorruptParticipantCount,
        minimumTurnout,
        releaseThreshold,
        setupContributorCount,
    } = deriveSupportedProfile(participantCount, optionCount);
    const foreign =
        foreignPoll === undefined
            ? undefined
            : await loadForeignPoll(foreignPoll, settings);
    // In a result run the last corrupt position equivocates, as in
    // the native result ceremony: two copies of its private state
    // sign two more ballots.
    const equivocator =
        setupDeparture ||
        unselectedCheckpoint ||
        noResult ||
        maximumCorruptParticipantCount === 0
            ? undefined
            : maximumCorruptParticipantCount;
    // The corrupt positions follow the organizer, as in the native
    // ceremonies; forgeries and altered state are shown to honest ones.
    const honest = (position: number) =>
        selectionFork
            ? position !== 0
            : setupDeparture || unselectedCheckpoint
              ? position !== 2
              : position === 0 || position > maximumCorruptParticipantCount;
    const copyNames = equivocator === undefined ? [] : ['conflicting', 'late'];
    // In a no-result run the last corrupt position runs a client that
    // signs an authentic invalid ballot, and casts it on time.
    const invalidAuthor =
        mode === 'no-result' && maximumCorruptParticipantCount > 0
            ? maximumCorruptParticipantCount
            : undefined;
    // The bounds the worker derives, as the independent models give
    // them, for the expected sizes of the cohort's records.
    const bounds = compileParticipantRuntimeProfile(
        participantCount,
        optionCount,
    );
    const eligibleContributorCount = bounds.eligibleContributorCount;
    // The schedule derives the eligible pool as the selected count
    // and the tolerated departures, which the bounds model must give.
    const departureSchedule = departures
        ? scheduleParticipantDepartures(participantCount, optionCount)
        : undefined;
    if (departureSchedule !== undefined)
        assert.equal(
            setupContributorCount + maximumCorruptParticipantCount,
            eligibleContributorCount,
        );
    // The proof randomness an honest ballot and release draw from
    // their seeds when no candidate is rejected, as the independent
    // models derive it.
    const proofDraws = compileOperationProofDraws(
        deriveSupportedProfile(participantCount, optionCount),
    );
    for (const file of [
        'tools/ci/run-participant-browser.ts',
        'tools/ci/participant-browser-cohort.ts',
        'tools/ci/participant-browser-relay.ts',
        'tools/ci/participant-browser-public-records.ts',
        'tools/ci/participant-browser-roster-completion.ts',
        'tools/ci/participant-browser-single-roster.ts',
        'tools/ci/participant-browser-two-rosters.ts',
        'tools/ci/participant-browser-fault-schedule.ts',
        'tools/ci/participant-browser-options.ts',
        'tools/ci/participant-workflow-measurements.ts',
        'tests/setup-selection-model.ts',
        'tests/threshold-completion-model.ts',
        'tools/ci/participant-padding-halt.ts',
        'tools/ci/participant-relay-record.ts',
        'tools/ci/participant-offer-announcements.ts',
        ...(mode === 'preparation' || unselectedCheckpoint
            ? [
                  'tools/ci/participant-padding-corruption.ts',
                  'tools/ci/participant-preparation-storage.ts',
              ]
            : []),
    ]) {
        const runnerSnapshot = path.join(log.runDirectoryPath, 'sources', file);
        await mkdir(path.dirname(runnerSnapshot), { recursive: true });
        await writeFile(runnerSnapshot, await readFile(file), {
            flag: 'wx',
        });
    }
    const { runtime, invalidBallotClient } = await assembleParticipantRuntime(
        log,
        invalidAuthor !== undefined,
    );
    const paddingClients =
        mode === 'preparation'
            ? new Map(
                  (['padding', 'final-slot'] as const).map((cut) => [
                      cut,
                      paddingHaltingClient(runtime.worker, cut),
                  ]),
              )
            : undefined;
    let preparationStorageBundle: string | undefined;
    if (mode === 'preparation' || unselectedCheckpoint) {
        const bundles = await build({
            config: false,
            clean: false,
            write: false,
            dts: false,
            entry: {
                preparationStorage: path.join(
                    root,
                    'tools/ci/participant-preparation-storage.ts',
                ),
            },
            format: 'iife',
            globalName: 'participantPreparationFixture',
            platform: 'browser',
            target: 'es2022',
            minify: false,
            sourcemap: false,
            report: false,
            logLevel: 'warn',
            failOnWarn: true,
            tsconfig: path.join(root, 'tsconfig.tools.json'),
            outputOptions: { codeSplitting: false },
        });
        const chunks = bundles.flatMap((bundle) => bundle.chunks);
        assert.equal(
            chunks.length,
            1,
            'The browser storage fixture must be self-contained.',
        );
        assert.equal(chunks[0].type, 'chunk');
        if (chunks[0].type === 'chunk')
            preparationStorageBundle = chunks[0].code;
        assert.ok(preparationStorageBundle);
        await writeFile(
            path.join(log.runDirectoryPath, 'preparation-storage-fixture.js'),
            preparationStorageBundle,
            { flag: 'wx' },
        );
        for (const client of paddingClients?.values() ?? [])
            await writeFile(
                path.join(
                    log.runDirectoryPath,
                    'padding-' + client.cut + '-worker.js',
                ),
                client.worker,
                { flag: 'wx' },
            );
    }
    const corrupt =
        invalidAuthor === undefined || invalidBallotClient === undefined
            ? undefined
            : { position: invalidAuthor, client: invalidBallotClient };
    assert.equal(corrupt === undefined, invalidAuthor === undefined);
    const corruptClient =
        corrupt === undefined
            ? undefined
            : {
                  position: corrupt.position,
                  feature: corrupt.client.feature,
                  module: corrupt.client.moduleDigest,
                  worker: corrupt.client.workerDigest,
              };
    if (corruptClient !== undefined)
        log.writeEvent({
            eventType: 'participant-corrupt-client',
            details: corruptClient,
        });
    // The relay stores every published record among the run's
    // artifacts.
    const publicDirectory = path.join(log.artifactDirectoryPath, 'public');
    await mkdir(publicDirectory, { recursive: true });
    const secondRosterDirectory =
        mode === 'rosters'
            ? path.join(log.artifactDirectoryPath, 'second-roster-public')
            : undefined;
    if (secondRosterDirectory !== undefined) await mkdir(secondRosterDirectory);
    const relay = await startRelay(
        settings,
        runtime,
        publicDirectory,
        corrupt,
        secondRosterDirectory,
        transfers,
    );
    cleanup.relay = relay;
    const {
        views,
        halting,
        delivered: deliveredRecords,
        candidateReads,
    } = relay;
    cleanup.profiles = await mkdtemp(
        path.join(root, 'temp/participant-browser-'),
    );
    const profileDirectory = cleanup.profiles;
    const allocationSummaries = new Map<
        string,
        {
            samples: number;
            peakFileBytes: number;
            peakAllocatedBytes: number;
            peakIndexedDatabaseFileBytes: number;
            peakIndexedDatabaseAllocatedBytes: number;
            missingEntries: number;
            unreadableEntries: number;
            skippedLinks: number;
            multiplyLinkedFileObservations: number;
        }
    >();
    const sampleStorageFiles = async (phase: 'running' | 'closed') => {
        const directories = [
            ...(await readdir(profileDirectory)).map((name) => ({
                key: name,
                directory: path.join(profileDirectory, name),
            })),
            {
                key: 'public transport',
                directory: path.join(publicDirectory, 'transport'),
            },
            {
                key: 'public with diagnostics',
                directory: publicDirectory,
            },
            ...(secondRosterDirectory === undefined
                ? []
                : [
                      {
                          key: 'second roster transport',
                          directory: path.join(
                              secondRosterDirectory,
                              'transport',
                          ),
                      },
                      {
                          key: 'second roster with diagnostics',
                          directory: secondRosterDirectory,
                      },
                  ]),
        ];
        const started = performance.now();
        const samples = await sampleFileAllocation(
            directories.map(({ directory }) => directory),
        );
        const finished = performance.now();
        for (const [index, sample] of samples.entries()) {
            const { key } = directories[index];
            const summary = allocationSummaries.get(key) ?? {
                samples: 0,
                peakFileBytes: 0,
                peakAllocatedBytes: 0,
                peakIndexedDatabaseFileBytes: 0,
                peakIndexedDatabaseAllocatedBytes: 0,
                missingEntries: 0,
                unreadableEntries: 0,
                skippedLinks: 0,
                multiplyLinkedFileObservations: 0,
            };
            summary.samples++;
            summary.peakFileBytes = Math.max(
                summary.peakFileBytes,
                sample.fileBytes,
            );
            summary.peakAllocatedBytes = Math.max(
                summary.peakAllocatedBytes,
                sample.allocatedBytes,
            );
            summary.peakIndexedDatabaseFileBytes = Math.max(
                summary.peakIndexedDatabaseFileBytes,
                sample.indexedDatabaseFileBytes,
            );
            summary.peakIndexedDatabaseAllocatedBytes = Math.max(
                summary.peakIndexedDatabaseAllocatedBytes,
                sample.indexedDatabaseAllocatedBytes,
            );
            summary.missingEntries += sample.missingEntries;
            summary.unreadableEntries += sample.unreadableEntries;
            summary.skippedLinks += sample.skippedLinks;
            summary.multiplyLinkedFileObservations +=
                sample.multiplyLinkedFiles;
            allocationSummaries.set(key, summary);
            log.writeEvent({
                eventType: 'participant-file-allocation',
                details: { key, phase, started, finished, ...sample },
            });
        }
    };
    cleanup.allocationMonitor = (async () => {
        while (cleanup.sampling) {
            await sampleStorageFiles('running');
            await delay(5000);
        }
    })().catch((error: unknown) => {
        cleanup.guardFailure ??=
            error instanceof Error ? error : new Error(String(error));
    });
    let allocationFinished = false;
    const finishAllocation = async () => {
        if (allocationFinished) return;
        allocationFinished = true;
        cleanup.sampling = false;
        await cleanup.monitor;
        await cleanup.allocationMonitor;
        await browsers.closeAll();
        await sampleStorageFiles('closed');
        await writeFile(
            path.join(log.runDirectoryPath, 'file-allocation-summary.json'),
            JSON.stringify(
                {
                    method:
                        process.platform === 'win32'
                            ? 'FILE_STANDARD_INFO AllocationSize and EndOfFile'
                            : 'lstat size and blocks times 512',
                    scope: 'Per-path default file streams, including browser database journals, Blob files and profile overhead. Transport-only directories are nested within the separately reported diagnostic public directories; those rows must not be added. Samples are not atomic snapshots, do not include volume metadata or filesystem journals, and can miss transient peaks and unlinked open files. Multiple hard links count by path and are reported explicitly.',
                    directories: Object.fromEntries(allocationSummaries),
                },
                null,
                2,
            ) + '\n',
            { flag: 'wx' },
        );
        if (cleanup.guardFailure !== undefined) throw cleanup.guardFailure;
    };
    cleanup.finishAllocation = finishAllocation;
    const peaks = new Array<number>(originCount).fill(0);
    const sampledResources = Array.from({ length: originCount }, () => ({
        browserProcessBytes: 0,
        javaScriptUsedBytes: null as number | null,
        javaScriptBackingBytes: null as number | null,
        originStorageBytes: null as number | null,
        incompleteHeapSamples: 0,
        missingStorageSamples: 0,
    }));
    const copyPeaks = new Map<string, number>();
    // Samples every open browser's process tree against the guard,
    // from one snapshot of the host's processes.
    cleanup.monitor = (async () => {
        while (cleanup.sampling) {
            const processes = await readProtocolProcesses();
            for (const { key, browser, sampled } of browsers.launched()) {
                const details = browserDetails.get(key);
                const bytes = sumProtocolProcessTree(
                    browser.processIdentifier,
                    processes,
                );
                if (details === undefined || bytes === undefined) continue;
                sampled(bytes);
                const heaps = browser.heaps();
                const storage = browser.storage();
                log.writeEvent({
                    eventType: 'participant-process-memory',
                    details: {
                        ...details,
                        bytes,
                        heaps,
                        storage,
                    },
                });
                // Chrome's own account of opening this launch's
                // IndexedDB stores, logged whenever it changes, so a
                // lost store shows whether Chrome discarded it.
                const openings = browser.backingStoreOpenings();
                const histograms = JSON.stringify(openings.histograms);
                if (
                    openings.reported &&
                    loggedOpenings.get(browser) !== histograms
                ) {
                    loggedOpenings.set(browser, histograms);
                    log.writeEvent({
                        eventType: 'participant-backing-store-openings',
                        details: {
                            ...details,
                            session: browserSessions.get(browser),
                            histograms: openings.histograms,
                        },
                    });
                }
                if (bytes > participantMemoryLimit) {
                    cleanup.guardFailure ??= new Error(
                        'Participant process-tree memory guard exceeded.',
                    );
                    await browsers.crash(key);
                }
                if (details.copy === undefined) {
                    const resources = sampledResources[details.position];
                    resources.browserProcessBytes = Math.max(
                        resources.browserProcessBytes,
                        bytes,
                    );
                    if (heaps.reported > 0) {
                        resources.javaScriptUsedBytes = Math.max(
                            resources.javaScriptUsedBytes ?? 0,
                            heaps.usedBytes,
                        );
                        resources.javaScriptBackingBytes = Math.max(
                            resources.javaScriptBackingBytes ?? 0,
                            heaps.backingBytes,
                        );
                    }
                    if (heaps.reported < heaps.sessions)
                        resources.incompleteHeapSamples++;
                    if (storage.reported)
                        resources.originStorageBytes = Math.max(
                            resources.originStorageBytes ?? 0,
                            storage.usageBytes,
                        );
                    else resources.missingStorageSamples++;
                    peaks[details.position] = Math.max(
                        peaks[details.position],
                        bytes,
                    );
                } else
                    copyPeaks.set(
                        details.copy,
                        Math.max(copyPeaks.get(details.copy) ?? 0, bytes),
                    );
            }
            await delay(2000);
        }
    })().catch((error: unknown) => {
        // Unsampled browsers leave the guard unenforced, so the run
        // fails once its running operations end.
        cleanup.guardFailure ??=
            error instanceof Error ? error : new Error(String(error));
    });
    const origin = (position: number) =>
        `http://127.0.0.1:${String(basePort + position)}`;
    const profile = (position: number) =>
        path.join(profileDirectory, `participant-${String(position)}`);
    const copyProfile = (copy: string) =>
        path.join(profileDirectory, `copy-${copy}`);
    const participantBrowser = (position: number) =>
        `participant-${String(position)}`;
    const copyBrowser = (copy: string) => `copy-${copy}`;
    // A departed participant's browser and private state are gone.
    // Its browser ends at once, as its device leaving would: the
    // shutdown work Chrome does for a profile about to be deleted is
    // no participant's, and after heavy storage churn it can outlast
    // any fixed deadline.
    const departed = new Set<number>();
    const depart = async (position: number) => {
        await browsers.crash(participantBrowser(position));
        departed.add(position);
        await rm(profile(position), {
            recursive: true,
            maxRetries: 10,
            retryDelay: 500,
        });
    };
    // Runs an action in a participant's browser, or in the browser of
    // a copy of its private state, opening the browser when it is not
    // open.
    const inBrowser = async <Result>(
        position: number,
        copy: string | undefined,
        action: (chrome: ChromeParticipant) => Promise<Result>,
    ) => {
        assert.ok(
            copy !== undefined || !departed.has(position),
            'The participant departed.',
        );
        assert.ok(
            copy === undefined || copies.get(copy) === position,
            'The copy does not exist.',
        );
        const key =
            copy === undefined
                ? participantBrowser(position)
                : copyBrowser(copy);
        const details = {
            position,
            ...(copy === undefined ? {} : { copy }),
        };
        return browsers.use(
            key,
            async () => {
                // This callback starts only after the pool has room;
                // pool queueing and another browser's eviction stay outside.
                const session = nextBrowserSession++;
                const launching = performance.now();
                let chrome: ChromeParticipant | undefined;
                try {
                    chrome = await launchChromeParticipant(
                        copy === undefined
                            ? profile(position)
                            : copyProfile(copy),
                        origin(position) +
                            (copy === secondRosterCopy ? secondRosterPath : ''),
                        copy === undefined && pressured.has(position)
                            ? `--wasm-max-mem-pages=${String(pressurePages)}`
                            : undefined,
                        // Chrome's own account of a store it could
                        // not open, or found corrupt and deleted,
                        // is recorded as it happens, so a crash
                        // cannot lose it.
                        (line) => {
                            log.writeEvent({
                                eventType: 'participant-browser-storage-log',
                                details: {
                                    ...details,
                                    session,
                                    line: redactDiagnosticText(line),
                                },
                            });
                        },
                    );
                    assert.equal(
                        await chrome.evaluate('crossOriginIsolated'),
                        !scalar,
                        'The browser isolation differs from the selected execution mode.',
                    );
                    assert.equal(
                        await chrome.evaluate(
                            "typeof window.runParticipant === 'function'",
                        ),
                        true,
                        'The participant page SDK did not initialize.',
                    );
                } catch (error) {
                    const bootstrap = {
                        session,
                        position,
                        started: launching,
                        finished: performance.now(),
                    };
                    if (
                        measureWorkflow &&
                        copy === undefined &&
                        position < participantCount
                    )
                        ordinaryBootstraps.push(bootstrap);
                    log.writeEvent({
                        eventType: 'participant-browser-bootstrap-failed',
                        details: { ...details, ...bootstrap },
                    });
                    await chrome?.crash();
                    throw error;
                }
                const bootstrap = {
                    session,
                    position,
                    started: launching,
                    finished: performance.now(),
                };
                browserDetails.set(key, details);
                browserSessions.set(chrome, session);
                if (
                    measureWorkflow &&
                    copy === undefined &&
                    position < participantCount
                )
                    ordinaryBootstraps.push(bootstrap);
                log.writeEvent({
                    eventType: 'participant-browser',
                    details: {
                        ...details,
                        ...bootstrap,
                        milliseconds: bootstrap.finished - bootstrap.started,
                        version: chrome.version,
                        launchArguments: chrome.launchArguments,
                        scalar,
                    },
                });
                return chrome;
            },
            action,
        );
    };
    // With profiling, each operation's summary of CPU samples, in
    // the order the operations ended.
    const cpuProfileDirectory = profiling
        ? path.join(log.runDirectoryPath, 'cpu-profiles')
        : undefined;
    if (cpuProfileDirectory !== undefined) await mkdir(cpuProfileDirectory);
    let profiledOperations = 0;
    const recoveryOperations = new Map<number, string>();
    // Runs one operation in a participant's page, or in a copy of its
    // private state.
    const request = async (
        position: number,
        operation: ParticipantOperation,
        parameters: Record<string, unknown> = {},
        copy?: string,
    ) =>
        inBrowser(position, copy, async (chrome) => {
            const started = performance.now();
            const measured =
                measureWorkflow &&
                copy === undefined &&
                position < participantCount
                    ? {
                          id: nextMeasuredOperation++,
                          position,
                          operation,
                          started,
                          stages: [...measuredStages[position]],
                          session: browserSessions.get(chrome)!,
                      }
                    : undefined;
            const recordAttempt = (
                outcome: ParticipantOperationMeasurement['outcome'],
                details?: Record<string, unknown>,
            ) => {
                if (measured === undefined) return;
                const resources = (details ?? {}) as Pick<
                    ParticipantOperationMeasurement,
                    'generation' | 'memory' | 'evaluationMemory'
                >;
                const entry = {
                    ...measured,
                    finished: performance.now(),
                    outcome,
                    generation: resources.generation,
                    memory: resources.memory,
                    evaluationMemory: resources.evaluationMemory,
                };
                ordinaryOperations.push(entry);
                log.writeEvent({
                    eventType: 'participant-visit-attempt',
                    details: entry,
                });
            };
            const beforeReads = new Map(relay?.reads[position]);
            const publicRecordReads = () =>
                [...(relay?.reads[position] ?? [])].flatMap(
                    ([route, value]) => {
                        const before = beforeReads.get(route);
                        const requests =
                            value.requests - (before?.requests ?? 0);
                        return requests === 0
                            ? []
                            : [
                                  {
                                      route,
                                      requests,
                                      bytes: value.bytes - (before?.bytes ?? 0),
                                  },
                              ];
                    },
                );
            const recovery =
                copy === undefined && recoveryOperations.has(position);
            const interruptedOperation = recovery
                ? recoveryOperations.get(position)
                : undefined;
            // The deadline ends with its operation so that no timer
            // outlives the run.
            const deadline = new AbortController();
            const evaluation = async () =>
                (await Promise.race([
                    chrome.evaluate(
                        `window.runParticipant(${JSON.stringify(operation)}, ${JSON.stringify(parameters)})`,
                    ),
                    delay(operationMilliseconds, undefined, {
                        signal: deadline.signal,
                    }).then(() => {
                        throw new Error('Participant operation deadline.');
                    }),
                ])) as WorkerResult;
            let result: WorkerResult;
            let cpuProfile: CpuProfileSummary | undefined;
            try {
                if (cpuProfileDirectory === undefined)
                    result = await evaluation();
                else {
                    const traced = await chrome.trace(evaluation);
                    result = traced.result;
                    cpuProfile = summarizeCpuTrace(
                        traced.events,
                        cpuProfileEntries,
                    );
                }
            } catch (error) {
                recordAttempt('interrupted');
                log.writeEvent({
                    eventType: 'participant-interrupted-operation',
                    details: {
                        position,
                        operation,
                        ...(copy === undefined ? {} : { copy }),
                        milliseconds: performance.now() - started,
                        recovery,
                        interruptedOperation,
                        originTransfer: { ...transfers[position] },
                        publicRecordReads: publicRecordReads(),
                    },
                });
                throw cleanup.guardFailure ?? error;
            } finally {
                deadline.abort();
            }
            assert.ok(result.status !== 'evaluated');
            recordAttempt(
                result.status,
                result.status === 'completed' ? result.details : undefined,
            );
            if (cleanup.guardFailure !== undefined) throw cleanup.guardFailure;
            if (scalar && result.status === 'completed')
                requireScalarMemory(result.details);
            const milliseconds = performance.now() - started;
            if (
                recovery &&
                result.status === 'completed' &&
                operation !== 'status'
            )
                recoveryOperations.delete(position);
            // A ballot or release generated in this visit drew the
            // modelled proof randomness.
            if (
                result.status === 'completed' &&
                result.details.proofRandomBytes !== undefined
            )
                assert.equal(
                    BigInt(result.details.proofRandomBytes as number),
                    operation === 'cast-ballot'
                        ? proofDraws.ballot
                        : proofDraws.release,
                    `${operation} at position ${String(position)} drew other proof randomness.`,
                );
            log.writeEvent({
                eventType: 'participant-operation',
                details: {
                    position,
                    ...(copy === undefined ? {} : { copy }),
                    operation,
                    milliseconds,
                    recovery,
                    interruptedOperation,
                    originTransfer: { ...transfers[position] },
                    publicRecordReads: publicRecordReads(),
                    result,
                },
            });
            if (cpuProfile !== undefined && cpuProfileDirectory !== undefined)
                await writeFile(
                    path.join(
                        cpuProfileDirectory,
                        `${String(++profiledOperations).padStart(4, '0')}-${String(position)}${copy === undefined ? '' : '-' + copy}-${operation}.json`,
                    ),
                    JSON.stringify(
                        {
                            position,
                            ...(copy === undefined ? {} : { copy }),
                            operation,
                            status: result.status,
                            milliseconds,
                            ...cpuProfile,
                        },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
            return result;
        });
    const run = async (
        position: number,
        operation: ParticipantOperation,
        parameters: Record<string, unknown> = {},
    ) => {
        const result = await request(position, operation, parameters);
        assert.ok(
            result.status === 'completed',
            `${operation} at position ${String(position)}: ${JSON.stringify(result)}`,
        );
        return result.details;
    };
    const expectStatus = async (
        position: number,
        operation: ParticipantOperation,
        status: WorkerResult['status'],
        parameters: Record<string, unknown> = {},
    ) => {
        const result = await request(position, operation, parameters);
        assert.equal(
            result.status,
            status,
            `${operation} at position ${String(position)}: ${JSON.stringify(result)}`,
        );
    };
    const positions = Array.from(
        { length: participantCount },
        (_unused, position) => position,
    );
    // In a result run of a profile that tolerates two corrupt
    // participants, the organizer's proposal can leave out two honest
    // ones, the last two before the last position. The departing one
    // leaves with its private state after preparation, casting
    // nothing. The relay hides the other's on-time ballot from every
    // other participant and delays its close response until the
    // proposal exists, so the proposal omits that ballot.
    const outsiders =
        mode === 'result' && maximumCorruptParticipantCount >= 2
            ? positions
                  .filter(
                      (position) =>
                          position > 0 &&
                          position < participantCount - 1 &&
                          honest(position),
                  )
                  .slice(-2)
            : [];
    const omittedVoter: number | undefined = outsiders[0];
    const departing: number | undefined = outsiders[1];
    // Reads the generation of a participant's committed head from its
    // own page, reading nothing else.
    const headGeneration = async (position: number, copy?: string) =>
        Number(
            await inBrowser(position, copy, (chrome) =>
                chrome.evaluate(
                    databaseScript(
                        participantDatabase,
                        `return (await result(database.transaction('head').objectStore('head').get(0)))?.generation ?? 0;`,
                    ),
                ),
            ),
        );
    const retainedHead = async (position: number, copy?: string) =>
        inBrowser(position, copy, (chrome) =>
            chrome.evaluate(
                databaseScript(
                    participantDatabase,
                    `return await result(database.transaction('head').objectStore('head').get(0));`,
                ),
            ),
        ) as Promise<{
            generation: number;
            hash: string;
            runtime: string;
        }>;
    // Counts a participant's records in one store from its own page,
    // reading none of them.
    const storedRecords = async (position: number, store: string) =>
        Number(
            await inBrowser(position, undefined, (chrome) =>
                chrome.evaluate(
                    databaseScript(
                        participantDatabase,
                        `return await result(database.transaction(${JSON.stringify(store)}).objectStore(${JSON.stringify(store)}).count());`,
                    ),
                ),
            ),
        );
    // Ends a participant's browser as a crash would. Its committed
    // state is what the next launch finds, while Chrome's own
    // shutdown can outlast its deadline when other browsers write.
    const endBrowser = async (position: number) => {
        await browsers.crash(participantBrowser(position));
    };
    // Runs a participant's operation in a browser that caps each
    // WebAssembly memory at the pressure pages. Exhausting that bound
    // leaves the participant pending, not stopped, whatever its
    // operation retained; the capped browser then ends.
    const pressure = async (
        position: number,
        operation: ParticipantOperation,
    ) => {
        await endBrowser(position);
        pressured.add(position);
        try {
            const before = await headGeneration(position);
            const result = await request(position, operation);
            assert.ok(
                result.status === 'pending' &&
                    result.cause === 'resource' &&
                    result.detail.includes('exhausted its memory bound'),
                `${operation} at position ${String(position)} under memory pressure: ${JSON.stringify(result)}`,
            );
            const details = {
                position,
                operation,
                pages: pressurePages,
                before,
                generation: await headGeneration(position),
                detail: result.detail,
            };
            memoryPressures.push(details);
            log.writeEvent({
                eventType: 'participant-memory-pressure',
                details,
            });
        } finally {
            await endBrowser(position);
            pressured.delete(position);
        }
    };
    // Copies a participant's private state into its own Chrome
    // profile at the participant's origin, whose browser opens when
    // the copy acts. The participant's browser ends first, so the
    // copy holds exactly the committed state its next launch would
    // find; crash reporting state is not participant state, and its
    // handler can outlive the browser.
    const copyState = async (position: number, copy: string) => {
        await endBrowser(position);
        await cp(profile(position), copyProfile(copy), {
            recursive: true,
            errorOnExist: true,
            force: false,
            filter: (source) =>
                path.relative(profile(position), source) !== 'Crashpad',
        });
        copies.set(copy, position);
    };
    const removeCopy = async (copy: string) => {
        await browsers.crash(copyBrowser(copy));
        copies.delete(copy);
        await rm(copyProfile(copy), {
            recursive: true,
            maxRetries: 10,
            retryDelay: 500,
        });
    };
    const sourceCustody: (SourceCustodyObservation & {
        position: number;
        stage: string;
    })[] = [];
    const sourceRefusals: Record<string, unknown>[] = [];
    const inspectSourceCustody = async (
        position: number,
        stage: string,
        copy?: string,
        mutation?: 'missing' | 'damaged',
    ) => {
        assert.ok(preparationStorageBundle);
        const observed = (await inBrowser(position, copy, (chrome) =>
            chrome.evaluate(
                preparationStorageBundle +
                    '\nparticipantPreparationFixture.inspectParticipantSourceCustody(' +
                    JSON.stringify({
                        namespace: participantNamespace,
                        runtimeIdentity: runtime.identity.runtime,
                        moduleDigest: runtime.identity.module,
                        mutation,
                    }) +
                    ');',
            ),
        )) as SourceCustodyObservation;
        const required = observed.generation < 12;
        assert.equal(
            observed.dataKeyBytes,
            required ? 3 * 32 : 2 * 32,
            'The root retained another data-key inventory.',
        );
        assert.equal(
            observed.sourceReferences,
            required ? 1 : 0,
            'The root retained another source reference inventory.',
        );
        assert.equal(
            observed.sourceRecords,
            required ? 1 : 0,
            'The data store retained another source capsule inventory.',
        );
        const details = { position, stage, ...observed };
        if (copy === undefined) sourceCustody.push(details);
        log.writeEvent({
            eventType: 'participant-source-custody',
            details: { ...details, copy, mutation },
        });
        return observed;
    };
    const refuseLostSource = async (
        position: number,
        operation: ParticipantOperation,
    ) => {
        assert.ok(honest(position));
        assert.ok(relay);
        for (const mutation of ['missing', 'damaged'] as const) {
            const copy = `source-${mutation}-${position}-${operation}`;
            await copyState(position, copy);
            try {
                const before = await retainedHead(position, copy);
                const observed = await inspectSourceCustody(
                    position,
                    'before fault',
                    copy,
                    mutation,
                );
                assert.ok(observed.generation < 12);
                const publications: number =
                    relay.publicationAttempts[position];
                const refused = await request(position, operation, {}, copy);
                assert.deepEqual(refused, {
                    status: 'stopped',
                    stopPersistence: 'confirmed',
                    detail:
                        mutation === 'missing'
                            ? 'Participant data inventory changed.'
                            : 'A participant data record changed.',
                });
                assert.deepEqual(
                    await retainedHead(position, copy),
                    before,
                    'A damaged source replaced the original root authority.',
                );
                await browsers.crash(copyBrowser(copy));
                const stopped = await request(position, 'status', {}, copy);
                assert.deepEqual(stopped, {
                    status: 'stopped',
                    stopPersistence: 'confirmed',
                    detail: 'Missing or inconsistent participant authority.',
                });
                const replacement = await request(
                    position,
                    'create',
                    {
                        role: 'joiner',
                        poll: organizer.poll,
                        definition: hexadecimal(definition),
                        definitionSignature: hexadecimal(definitionSignature),
                        username: 'Replacement refused',
                    },
                    copy,
                );
                assert.deepEqual(replacement, {
                    status: 'refused',
                    reason: 'participant exists',
                });
                assert.deepEqual(await retainedHead(position, copy), before);
                assert.equal(
                    relay.publicationAttempts[position],
                    publications,
                    'A source fault caused a relay publication attempt.',
                );
                const details = {
                    position,
                    generation: observed.generation,
                    operation,
                    mutation,
                    result: refused,
                    coldResult: stopped,
                    replacement,
                    publicationAttempts: 0,
                };
                sourceRefusals.push(details);
                log.writeEvent({
                    eventType: 'participant-source-refusal',
                    details,
                });
            } finally {
                await removeCopy(copy);
            }
        }
    };
    // Loses the last record of one store in a copy of an honest
    // participant's state and runs the operation there: the copy
    // stops with its stop persisted and stays stopped, and the copy
    // is deleted. The participant itself continues unaffected.
    const stateLosses: {
        position: number;
        store: string;
        record: unknown;
        operation: ParticipantOperation;
        generation: number;
        detail: string;
    }[] = [];
    const loseState = async (
        position: number,
        store: string,
        operation: ParticipantOperation,
        noPublications = false,
    ) => {
        assert.ok(honest(position), 'Only honest state is lost.');
        const copy = `lost-${store}-${String(position)}`;
        await copyState(position, copy);
        try {
            const generation = await headGeneration(position, copy);
            const record: unknown = await inBrowser(position, copy, (chrome) =>
                chrome.evaluate(
                    databaseScript(
                        participantDatabase,
                        `const deleting = database.transaction(${JSON.stringify(store)}, 'readwrite');
const deleted = completion(deleting);
const cursor = await result(deleting.objectStore(${JSON.stringify(store)}).openCursor(null, 'prev'));
if (cursor === null) throw new Error('No record to lose.');
const key = cursor.key;
cursor.delete();
await deleted;
return key;`,
                    ),
                ),
            );
            const publicationAttempts = relay.publicationAttempts[position];
            const result = await request(position, operation, {}, copy);
            assert.ok(
                result.status === 'stopped' &&
                    result.stopPersistence === 'confirmed',
                `${operation} after losing a ${store} record at position ${String(position)}: ${JSON.stringify(result)}`,
            );
            assert.deepEqual(await request(position, 'status', {}, copy), {
                status: 'stopped',
                detail: 'Missing or inconsistent participant authority.',
                stopPersistence: 'confirmed',
            });
            if (noPublications)
                assert.equal(
                    relay.publicationAttempts[position],
                    publicationAttempts,
                    'Missing required preparation state caused a relay publication.',
                );
            const loss = {
                position,
                store,
                record,
                operation,
                generation,
                detail: result.detail,
                ...(noPublications ? { publicationAttempts: 0 } : {}),
            };
            stateLosses.push(loss);
            log.writeEvent({
                eventType: 'participant-state-loss',
                details: loss,
            });
        } finally {
            await removeCopy(copy);
        }
    };
    // Installs a halting client by reloading the idle page. The
    // requested protocol cut performs the crash; arming a hook must
    // not add another crash during inspection or browser recovery.
    const armHalt = async (position: number, generation: number) => {
        assert.ok(honest(position), 'Only an honest client halts.');
        halting.set(position, haltingClient(runtime.worker, generation));
        await inBrowser(position, undefined, (chrome) => chrome.reload());
    };
    // Runs an operation in a halting client. The browser crashes once
    // its participant enters the generation, with no shutdown work
    // after that commit, and the next visit runs the runtime's own
    // worker again.
    const interruptions: {
        position: number;
        operation: ParticipantOperation;
        generation: number;
        // The records an interrupted operation had stored ahead of
        // its next root.
        staged?: Readonly<{ store: string; records: number }>;
        // The public record the relay had delivered to the
        // interrupted operation.
        delivered?: string;
        preparation?: PreparationCut;
    }[] = [];
    const interrupt = async (
        position: number,
        operation: ParticipantOperation,
        parameters: Record<string, unknown>,
        generation: number,
    ) => {
        if (halting.get(position)?.generation !== generation)
            await armHalt(position, generation);
        try {
            const halted = request(position, operation, parameters);
            for (;;) {
                const settled = await Promise.race([
                    halted.then(
                        (result) => JSON.stringify(result),
                        (error: unknown) => String(error),
                    ),
                    delay(500, undefined),
                ]);
                assert.equal(
                    settled,
                    undefined,
                    `${operation} at position ${String(position)} ended before generation ${String(generation)}: ${String(settled)}`,
                );
                if ((await headGeneration(position)) === generation) break;
            }
            await endBrowser(position);
            await assert.rejects(halted);
        } finally {
            halting.delete(position);
        }
        recoveryOperations.set(position, operation);
        interruptions.push({ position, operation, generation });
        log.writeEvent({
            eventType: 'participant-interruption',
            details: { position, operation, generation },
        });
    };
    const interruptPreparation = async (
        position: number,
        operation: ParticipantOperation,
        cut: PreparationCut,
    ) => {
        assert.ok(honest(position));
        halting.set(position, preparationHaltingClient(runtime.worker, cut));
        await inBrowser(position, undefined, (chrome) => chrome.reload());
        try {
            const pending = request(position, operation);
            for (;;) {
                const outcome = await Promise.race([
                    pending.then(
                        (result) => JSON.stringify(result),
                        (error: unknown) => String(error),
                    ),
                    delay(250, undefined),
                ]);
                assert.equal(
                    outcome,
                    undefined,
                    `${operation} ended before ${cut.kind} phase ${String(cut.phase)}: ${String(outcome)}`,
                );
                const reached = await inBrowser(position, undefined, (chrome) =>
                    chrome.evaluate('window.preparationHalt'),
                );
                if (reached !== null && reached !== undefined) {
                    assert.deepEqual(reached, {
                        type: 'participant-preparation-halt',
                        ...cut,
                    });
                    break;
                }
            }
            assert.equal(await headGeneration(position), 4);
            await endBrowser(position);
            await assert.rejects(pending);
        } finally {
            halting.delete(position);
        }
        recoveryOperations.set(position, operation);
        interruptions.push({
            position,
            operation,
            generation: 4,
            preparation: cut,
        });
        log.writeEvent({
            eventType: 'participant-preparation-interruption',
            details: { position, operation, ...cut },
        });
    };
    // Crashes a participant's browser while its operation, in the
    // generation it durably entered, has reached a point ahead of its
    // next root, and records that point. The next visit discards what
    // the operation stored and runs it again from its retained state.
    const interruptWhen = async (
        position: number,
        operation: ParticipantOperation,
        generation: number,
        reached: () => Promise<boolean>,
        point: () => Promise<
            Pick<(typeof interruptions)[number], 'staged' | 'delivered'>
        >,
    ) => {
        const interrupted = request(position, operation);
        for (;;) {
            const outcome = await Promise.race([
                interrupted.then(
                    () => 'settled',
                    () => 'settled',
                ),
                delay(250, 'waiting'),
            ]);
            assert.equal(
                outcome,
                'waiting',
                `${operation} at position ${String(position)} ended before its interruption in generation ${String(generation)}.`,
            );
            if (
                (await headGeneration(position)) === generation &&
                (await reached())
            )
                break;
        }
        await endBrowser(position);
        await assert.rejects(interrupted);
        assert.equal(
            await headGeneration(position),
            generation,
            'The interrupted operation committed its next root first.',
        );
        const details = {
            position,
            operation,
            generation,
            ...(await point()),
        };
        recoveryOperations.set(position, operation);
        interruptions.push(details);
        log.writeEvent({
            eventType: 'participant-interruption',
            details,
        });
    };
    // Interrupts an operation once it stored at least the given
    // records in one store.
    const interruptStaged = (
        position: number,
        operation: ParticipantOperation,
        generation: number,
        store: string,
        records: number,
    ) =>
        interruptWhen(
            position,
            operation,
            generation,
            async () => (await storedRecords(position, store)) >= records,
            async () => ({
                staged: {
                    store,
                    records: await storedRecords(position, store),
                },
            }),
        );
    const paddingInterruptions: {
        position: number;
        observation: Readonly<{
            slots: readonly PaddingSlotObservation[];
            halt: PaddingHaltObservation;
        }>;
        head: Readonly<{
            generation: number;
            hash: string;
            runtime: string;
        }>;
        checkpointRecords: number;
        originalWorkerSha512: string;
        instrumentedWorkerSha512: string;
        instrumentationMilliseconds: number;
    }[] = [];
    const interruptPadding = async (position: number, cut: PaddingCut) => {
        const client = paddingClients?.get(cut);
        assert.ok(client);
        halting.set(position, client);
        await inBrowser(position, undefined, (chrome) => chrome.reload());
        try {
            const before = await retainedHead(position);
            assert.equal(before.generation, 4);
            const checkpointRecords = await storedRecords(
                position,
                'checkpoint',
            );
            assert.ok(checkpointRecords > 0);
            const interrupted = request(position, 'contribute');
            let observation: {
                slots: PaddingSlotObservation[];
                halt: PaddingHaltObservation | null;
            };
            for (;;) {
                const settled = await Promise.race([
                    interrupted.then(
                        () => true,
                        () => true,
                    ),
                    delay(250, false),
                ]);
                assert.equal(
                    settled,
                    false,
                    'Contribution ended without reaching the requested padding cut; no reseed or skipped case is allowed.',
                );
                observation = (await inBrowser(position, undefined, (chrome) =>
                    chrome.evaluate('window.paddingReplay'),
                )) as typeof observation;
                if (observation.halt !== null) break;
            }
            assert.ok(observation.halt);
            assert.equal(observation.halt.cut, cut);
            const captured = {
                slots: observation.slots,
                halt: observation.halt,
            };
            validatePaddingObservation(
                captured,
                bounds.contribution,
                chunkBytes,
            );
            assert.deepEqual(
                await retainedHead(position),
                before,
                'Padding changed its original continuation root before the cut.',
            );
            assert.equal(
                await storedRecords(position, 'checkpoint'),
                checkpointRecords,
            );
            assert.equal(
                await storedRecords(position, 'contribution'),
                bounds.contribution.publicRecords.length +
                    captured.slots.length,
            );
            await endBrowser(position);
            await assert.rejects(interrupted);
            const entry = {
                position,
                observation: captured,
                head: before,
                checkpointRecords,
                originalWorkerSha512: client.originalDigest,
                instrumentedWorkerSha512: client.digest,
                instrumentationMilliseconds: captured.slots.reduce(
                    (sum, slot) => sum + slot.instrumentationMilliseconds,
                    0,
                ),
            };
            paddingInterruptions.push(entry);
            interruptions.push({
                position,
                operation: 'contribute',
                generation: 4,
                preparation: { kind: 'contribution', phase: 6 },
                staged: {
                    store: 'contribution',
                    records:
                        bounds.contribution.publicRecords.length +
                        captured.slots.length,
                },
            });
            recoveryOperations.set(position, 'contribute');
            log.writeEvent({
                eventType: 'participant-padding-interruption',
                details: entry,
            });
        } finally {
            halting.delete(position);
        }
    };
    // Interrupts an operation once the relay delivered it the named
    // public record.
    const interruptDelivered = (
        position: number,
        operation: ParticipantOperation,
        generation: number,
        name: string,
    ) => {
        deliveredRecords[position].clear();
        return interruptWhen(
            position,
            operation,
            generation,
            () => Promise.resolve(deliveredRecords[position].has(name)),
            () => Promise.resolve({ delivered: name }),
        );
    };
    // Each participant scores every option differently, across the
    // supported score range, and the result lists one option fewer
    // than the complete ranking. In a result run the first honest
    // participant after the organizer casts the all-minimum ballot,
    // an ordinary valid ballot that counts like any other.
    const { minimumScore, maximumScore } = bounds.ballot;
    const minimumBallotAuthor =
        mode === 'result'
            ? positions.find((position) => position > 0 && honest(position))
            : undefined;
    const ballotScores = (position: number) =>
        Array.from({ length: optionCount }, (_unused, option) =>
            position === minimumBallotAuthor
                ? minimumScore
                : minimumScore +
                  ((position * (optionCount + 1) + option) %
                      (maximumScore - minimumScore + 1)),
        );
    const question =
        mode === 'preparation'
            ? 'Verify original participant preparation'
            : 'Verify the complete signed ballot path';
    const labels = Array.from(
        { length: optionCount },
        (_unused, index) => `Option ${String(index)}`,
    );
    const hexadecimal = (bytes: Uint8Array) =>
        Buffer.from(bytes).toString('hex');
    // The poll admits exactly the roster's participants.
    const organizer = await run(0, 'create', {
        role: 'organizer',
        question,
        options: labels,
        topCount,
        maximumParticipants: participantCount,
        username: 'Organizer',
    });
    assert.equal(organizer.isOrganizer, true);
    // Every participant reports the poll its module verified: the
    // question, each option's identifier and label, and the result
    // length.
    const verifiedPoll = (details: Record<string, unknown>) => ({
        question: details.question,
        options: details.options,
        topCount: details.topCount,
    });
    const createdPoll = {
        question,
        options: labels.map((label, index) => ({
            identifier: `option-${String(index)}`,
            label,
        })),
        topCount,
    };
    assert.deepEqual(verifiedPoll(organizer), createdPoll);
    // The page asked the browser to keep the origin's storage, which
    // it grants by its own policy.
    assert.equal(typeof organizer.isStoragePersistent, 'boolean');
    await run(0, 'publish');
    // An operation on an empty namespace is refused and leaves it
    // empty, so that participant still joins below.
    if (mode !== 'plain') await expectStatus(1, 'status', 'refused');
    const definition = await readFile(
        path.join(publicDirectory, 'poll-definition.bin'),
    );
    const definitionSignature = await readFile(
        path.join(publicDirectory, 'poll-signature.bin'),
    );
    const join = async (position: number, username: string) => {
        const details = await run(position, 'create', {
            role: 'joiner',
            poll: organizer.poll,
            definition: hexadecimal(definition),
            definitionSignature: hexadecimal(definitionSignature),
            username,
        });
        assert.equal(details.isOrganizer, false);
        assert.equal(details.poll, organizer.poll);
        assert.deepEqual(verifiedPoll(details), createdPoll);
        await run(position, 'publish');
        return details;
    };
    // A roster member acts at its origin, or in a copy of the
    // organizer's private state.
    const act = async (
        member: Member,
        operation: ParticipantOperation,
        parameters: Record<string, unknown> = {},
    ) => {
        const result = await request(
            member.origin,
            operation,
            parameters,
            member.copy,
        );
        assert.ok(
            result.status === 'completed',
            `${operation} at origin ${String(member.origin)}${member.copy === undefined ? '' : ' in copy ' + member.copy}: ${JSON.stringify(result)}`,
        );
        return result.details;
    };
    // A roster's record identifiers: the organizer's registration,
    // then the joined participants' in order.
    const rosterRecordIds = (joined: readonly Record<string, unknown>[]) =>
        [organizer, ...joined].map((details) =>
            String(details.registrationBodyDigest),
        );
    // The ordered option identifiers the scores rank first.
    const rankedIdentifiers = (scores: readonly (readonly number[])[]) => {
        const optionTotals = Array.from(
            { length: optionCount },
            (_unused, option) =>
                scores.reduce((total, score) => total + score[option], 0),
        );
        return Array.from({ length: optionCount }, (_unused, option) => option)
            .sort(
                (left, right) =>
                    optionTotals[right] - optionTotals[left] || left - right,
            )
            .slice(0, topCount)
            .map((option) => `option-${String(option)}`);
    };
    const setupDiscoveryFaults: Record<string, unknown>[] = [];
    const publicationRecoveryEvidence: Record<string, unknown>[] = [];
    const incompleteResponseEvidence: Record<string, unknown>[] = [];
    const unselectedCheckpointEvidence: Record<string, unknown>[] = [];
    const selectionForkEvidence: Record<string, unknown>[] = [];
    const inspectCheckpoint = async (
        stage: string,
        copy?: string,
        damageCheckpoint = false,
    ) => {
        assert.ok(preparationStorageBundle);
        const started = performance.now();
        const observation = (await inBrowser(1, copy, (chrome) =>
            chrome.evaluate(
                preparationStorageBundle +
                    '\nparticipantPreparationFixture.inspectParticipantCheckpointCustody(' +
                    JSON.stringify({
                        namespace: participantNamespace,
                        runtimeIdentity: runtime.identity.runtime,
                        moduleDigest: runtime.identity.module,
                        damageCheckpoint,
                    }) +
                    ');',
            ),
        )) as CheckpointCustodyObservation;
        assert.equal(observation.position, 1);
        const entry = {
            stage,
            copy,
            ...observation,
            instrumentationMilliseconds: performance.now() - started,
        };
        unselectedCheckpointEvidence.push(entry);
        log.writeEvent({
            eventType: 'participant-unselected-checkpoint',
            details: entry,
        });
        return observation;
    };
    const sameOwnCheckpoint = (
        before: CheckpointCustodyObservation,
        after: CheckpointCustodyObservation,
    ) => {
        for (const field of [
            'phase',
            'position',
            'ownJournalSha512',
            'headerSha512',
            'recordInventorySha512',
            'contributionRecords',
            'checkpointRecords',
        ] as const)
            assert.deepEqual(
                after[field],
                before[field],
                'Endorsement changed the original own checkpoint: ' + field,
            );
    };
    const probe = async (
        position: number,
        forgeries: ReadonlyMap<string, ViewedRecord>,
        detail: string | readonly string[],
    ) => {
        deliveredRecords[position].clear();
        candidateReads[position].clear();
        for (const [name, bytes] of forgeries) views[position].set(name, bytes);
        try {
            const result = await request(position, 'compute-result');
            assert.ok(result.status === 'pending');
            const details = typeof detail === 'string' ? [detail] : detail;
            assert.ok(details.includes(result.detail), result.detail);
            assert.deepEqual(result, {
                status: 'pending',
                cause: 'public input',
                detail: result.detail,
            });
            if ([...forgeries.values()].some((value) => value !== undefined))
                assert.ok(
                    [...forgeries.keys()].some((name) =>
                        deliveredRecords[position].has(name),
                    ),
                    'The refused operation did not read its forged inputs.',
                );
            return result.detail;
        } finally {
            views[position].clear();
        }
    };
    // A result visit that reads none of the served records completes.
    const probeUnread = async (
        position: number,
        forgeries: ReadonlyMap<string, ViewedRecord>,
    ) => {
        deliveredRecords[position].clear();
        for (const [name, bytes] of forgeries) views[position].set(name, bytes);
        try {
            const result = await run(position, 'compute-result');
            assert.ok(
                [...forgeries.keys()].every(
                    (name) => !deliveredRecords[position].has(name),
                ),
                'The cached result consumed a replaced input.',
            );
            return result;
        } finally {
            views[position].clear();
        }
    };
    return {
        ...settings,
        log,
        browsers,
        memoryPressures,
        ordinaryOperations,
        ordinaryBootstraps,
        measureWorkflow,
        measuredStages,
        transfers,
        maximumCorruptParticipantCount,
        minimumTurnout,
        releaseThreshold,
        setupContributorCount,
        foreign,
        equivocator,
        honest,
        copyNames,
        invalidAuthor,
        bounds,
        eligibleContributorCount,
        departureSchedule,
        runtime,
        preparationStorageBundle,
        corruptClient,
        publicDirectory,
        secondRosterDirectory,
        relay,
        views,
        deliveredRecords,
        candidateReads,
        finishAllocation,
        peaks,
        sampledResources,
        copyPeaks,
        origin,
        copyBrowser,
        departed,
        depart,
        inBrowser,
        recoveryOperations,
        request,
        run,
        expectStatus,
        positions,
        outsiders,
        omittedVoter,
        departing,
        headGeneration,
        retainedHead,
        storedRecords,
        endBrowser,
        pressure,
        copyState,
        removeCopy,
        sourceCustody,
        sourceRefusals,
        inspectSourceCustody,
        refuseLostSource,
        stateLosses,
        loseState,
        interruptions,
        interrupt,
        interruptPreparation,
        interruptStaged,
        paddingInterruptions,
        interruptPadding,
        interruptDelivered,
        minimumBallotAuthor,
        ballotScores,
        hexadecimal,
        organizer,
        definition,
        definitionSignature,
        join,
        act,
        rosterRecordIds,
        rankedIdentifiers,
        setupDiscoveryFaults,
        publicationRecoveryEvidence,
        incompleteResponseEvidence,
        unselectedCheckpointEvidence,
        selectionForkEvidence,
        inspectCheckpoint,
        sameOwnCheckpoint,
        probe,
        probeUnread,
    };
};

export type ParticipantCohort = Awaited<
    ReturnType<typeof openParticipantCohort>
>;

// Stops the monitors, closes every browser and the relay, records the
// transfers, and deletes the profiles of a completed run.
export const closeParticipantCohort = async (
    state: CohortState,
    log: ActiveLocalRunLog,
) => {
    const { browsers, transfers, cleanup } = state;
    cleanup.sampling = false;
    await cleanup.monitor;
    await cleanup.allocationMonitor;
    await browsers.closeAll();
    for (const server of cleanup.relay?.servers ?? [])
        await new Promise((resolve) => server.close(resolve));
    try {
        await cleanup.finishAllocation?.();
    } catch (error) {
        cleanup.guardFailure ??=
            error instanceof Error ? error : new Error(String(error));
    }
    if (cleanup.guardFailure !== undefined) cleanup.completed = false;
    log.writeEvent({
        eventType: 'participant-transfer-summary',
        details: { participants: transfers },
    });
    if (cleanup.profiles !== undefined && cleanup.completed)
        await rm(cleanup.profiles, { recursive: true, force: true });
    else if (cleanup.profiles !== undefined)
        log.writeEvent({
            eventType: 'participant-checkpoint-preserved',
            details: { directory: cleanup.profiles, runtimeBound: true },
        });
};
