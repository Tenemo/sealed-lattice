import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { build } from 'tsdown';

import { compileOperationProofDraws } from '#tests/operation-seed-model.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import {
    type ChromeParticipant,
    launchChromeParticipant,
} from '#tools/ci/chrome-session.js';
import { importClosure } from '#tools/ci/import-closure.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';
import { createParticipantInterruptions } from '#tools/ci/participant-browser-interruptions.js';
import { scheduleParticipantDepartures } from '#tools/ci/participant-browser-options.js';
import { loadForeignPoll } from '#tools/ci/participant-browser-public-records.js';
import {
    type ViewedRecord,
    participantNamespace,
    secondRosterPath,
    startRelay,
} from '#tools/ci/participant-browser-relay.js';
import { createParticipantRequests } from '#tools/ci/participant-browser-requests.js';
import { startParticipantResourceSampling } from '#tools/ci/participant-browser-resources.js';
import { createParticipantStateFaults } from '#tools/ci/participant-browser-state-faults.js';
import {
    type ParticipantBrowserSettings,
    type CohortState,
    secondRosterCopy,
    pressurePages,
    type ParticipantOperation,
    type Member,
} from '#tools/ci/participant-cohort-state.js';
import { paddingHaltingClient } from '#tools/ci/participant-padding-halt.js';
import type { CheckpointCustodyObservation } from '#tools/ci/participant-preparation-storage.js';
import { assembleParticipantRuntime } from '#tools/ci/participant-runtime-assembly.js';
import { redactDiagnosticText } from '#tools/ci/run-log-diagnostics.js';
import { snapshotRunSources } from '#tools/ci/run-sources.js';

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
        cpuProfiling,
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
    const { runtime, invalidBallotClient } = await assembleParticipantRuntime(
        log,
        invalidAuthor !== undefined,
    );
    // The runner's own sources, every repository file it imports, and the
    // browser entry it bundles by path, beside the runtime sources the
    // assembly recorded.
    await snapshotRunSources(
        log,
        root,
        await importClosure(
            [
                'tools/ci/run-participant-browser.ts',
                'tools/ci/participant-preparation-storage.ts',
            ],
            root,
        ),
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
        const handle = await build({
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
        const chunks = handle.bundles.flatMap((bundle) => bundle.chunks);
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
    const { finishAllocation, peaks, sampledResources, copyPeaks } =
        startParticipantResourceSampling({
            profileDirectory,
            publicDirectory,
            secondRosterDirectory,
            log,
            cleanup,
            browsers,
            originCount,
            browserDetails,
            loggedOpenings,
            browserSessions,
        });

    const origin = (position: number) =>
        `http://127.0.0.1:${String(basePort + position)}`;
    const browserProfilePath = (position: number) =>
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
        await rm(browserProfilePath(position), {
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
                            ? browserProfilePath(position)
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
                        // A close that waited long for Chrome to exit is
                        // recorded with what of Chrome still ran.
                        (slowClose) => {
                            log.writeEvent({
                                eventType: 'participant-browser-slow-close',
                                details: { ...details, session, ...slowClose },
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
    const { request, recoveryOperations, run, expectStatus } =
        await createParticipantRequests({
            cpuProfiling,
            log,
            inBrowser,
            measureWorkflow,
            participantCount,
            measuredStages,
            browserSessions,
            ordinaryOperations,
            relay,
            transfers,
            cleanup,
            scalar,
            proofDraws,
        });

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
    assert.ok(
        'isStoragePersistent' in organizer &&
            typeof organizer.isStoragePersistent === 'boolean',
    );
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
    const {
        headGeneration,
        endBrowser,
        storedRecords,
        retainedHead,
        pressure,
        copyState,
        removeCopy,
        sourceCustody,
        sourceRefusals,
        inspectSourceCustody,
        refuseLostSource,
        stateLosses,
        loseState,
    } = createParticipantStateFaults({
        inBrowser,
        browsers,
        participantBrowser,
        pressured,
        request,
        memoryPressures,
        log,
        browserProfilePath,
        copyProfile,
        copies,
        copyBrowser,
        preparationStorageBundle,
        runtime,
        honest,
        relay,
        organizer,
        hexadecimal,
        definition,
        definitionSignature,
    });

    const {
        interruptions,
        interrupt,
        interruptPreparation,
        interruptStaged,
        paddingInterruptions,
        interruptPadding,
        interruptDelivered,
    } = createParticipantInterruptions({
        honest,
        halting,
        runtime,
        inBrowser,
        request,
        headGeneration,
        endBrowser,
        recoveryOperations,
        log,
        browsers,
        participantBrowser,
        storedRecords,
        paddingClients,
        retainedHead,
        bounds,
        deliveredRecords,
    });

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
