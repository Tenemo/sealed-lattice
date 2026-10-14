import assert from 'node:assert/strict';
import { readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import type { WorkerResult } from '#packages/sdk/src/participant/worker/runtime/worker-messages.js';
import { tupleFields } from '#packages/sdk/src/participant/worker/shared/bytes.js';
import { targetPhase } from '#packages/sdk/src/participant/worker/storage/root-generation.js';
import {
    encodeSetupSelectionModel,
    setupSelectionIdentityModel,
} from '#tests/setup-selection-wire-model.js';
import { type ParticipantCohort } from '#tools/ci/participant-browser-cohort.js';
import { generatedOfferIdentity } from '#tools/ci/participant-browser-public-records.js';
import { completeRoster } from '#tools/ci/participant-browser-roster-completion.js';
import { requireScalarMemory } from '#tools/ci/participant-cohort-state.js';
import { summarizeParticipantWorkflow } from '#tools/ci/participant-workflow-measurements.js';

// Carries one roster through each stage once, with the recovery,
// departure, setup and publication schedules the options select.
export const runSingleRoster = async (cohort: ParticipantCohort) => {
    const {
        participantCount,
        optionCount,
        mode,
        cpuProfiling,
        scalar,
        setupDeparture,
        unselectedCheckpoint,
        selectionFork,
        publicationFaults,
        sequential,
        measureRecovery,
        departures,
        topCount,
        leftOut,
        log,
        memoryPressures,
        ordinaryOperations,
        ordinaryBootstraps,
        measureWorkflow,
        transfers,
        maximumCorruptParticipantCount,
        setupContributorCount,
        bounds,
        eligibleContributorCount,
        departureSchedule,
        runtime,
        publicDirectory,
        relay,
        peaks,
        sampledResources,
        departed,
        depart,
        inBrowser,
        recoveryOperations,
        positions,
        interruptions,
        ballotScores,
        organizer,
        join,
        rosterRecordIds,
        setupDiscoveryFaults,
        publicationRecoveryEvidence,
        incompleteResponseEvidence,
        unselectedCheckpointEvidence,
        selectionForkEvidence,
    } = cohort;
    // Every other participant joins, and the roster completes
    // each stage once.
    const joined = await Promise.all(
        positions
            .slice(1)
            .map((position) =>
                join(position, `Participant ${String(position)}`),
            ),
    );
    const plainRecordIds = rosterRecordIds(joined);
    const identifiers = await completeRoster(
        cohort,
        positions.map((position) => ({ origin: position })),
        plainRecordIds,
        positions.map(ballotScores),
        setupDeparture ? 1 : undefined,
    );
    let independentOutcome: WorkerResult | undefined;
    let standaloneMilliseconds: number | undefined;
    let certificateEndorsers: number[] | undefined;
    if (measureRecovery) {
        assert.deepEqual(
            interruptions.map((cut) => [
                cut.position,
                cut.operation,
                cut.preparation?.phase ?? cut.generation,
            ]),
            [
                [0, 'contribute', 5],
                [0, 'cast-ballot', 15],
                [0, 'sign-target', targetPhase.locked],
                [0, 'release', 27],
            ],
        );
        assert.equal(
            ordinaryOperations.filter(
                (operation) => operation.outcome === 'interrupted',
            ).length,
            4,
        );
        assert.equal(recoveryOperations.size, 0);
        for (const position of positions) await depart(position);
        const started = performance.now();
        independentOutcome = (await inBrowser(leftOut, undefined, (chrome) =>
            chrome.evaluate(
                'window.verifyOutcome(' + JSON.stringify(organizer.poll) + ')',
            ),
        )) as WorkerResult;
        standaloneMilliseconds = performance.now() - started;
        assert.ok(independentOutcome.status === 'completed');
        assert.deepEqual(independentOutcome.details.identifiers, identifiers);
        if (scalar) requireScalarMemory(independentOutcome.details);
        log.writeEvent({
            eventType: 'participant-recovery-public-outcome',
            details: {
                milliseconds: standaloneMilliseconds,
                retiredOriginalParticipants: [...departed],
                independentOutcome,
            },
        });
    }

    if (setupDeparture || unselectedCheckpoint) {
        assert.deepEqual(
            [...departed],
            setupDeparture ? (participantCount === 7 ? [1, 2] : [1]) : [],
        );
        assert.equal(
            await stat(path.join(publicDirectory, 'contribution-1')).catch(
                () => undefined,
            ),
            undefined,
        );
        if (setupDeparture)
            assert.equal(
                await stat(
                    path.join(publicDirectory, 'selection-endorsement-1.bin'),
                ).catch(() => undefined),
                undefined,
            );
        const selection = await readFile(
            path.join(publicDirectory, 'selection.bin'),
        );
        const fields = tupleFields(selection);
        assert.equal(fields.length, 3);
        const rosterIdentity = Buffer.from(fields[1]).toString('hex');
        const selected = await Promise.all(
            positions
                .filter(
                    (position) =>
                        position < eligibleContributorCount && position !== 1,
                )
                .slice(0, setupContributorCount)
                .map(async (position) => ({
                    position,
                    bodyIdentity: (
                        await generatedOfferIdentity(publicDirectory, position)
                    ).toString('hex'),
                })),
        );
        assert.deepEqual(
            selection,
            encodeSetupSelectionModel(
                participantCount,
                rosterIdentity,
                selected,
            ),
        );
        assert.equal(
            (
                await readFile(path.join(publicDirectory, 'setup-identity.bin'))
            ).toString('hex'),
            setupSelectionIdentityModel(
                participantCount,
                rosterIdentity,
                selected,
            ),
        );
        const certificate = await readFile(
            path.join(publicDirectory, 'setup-certificate.bin'),
        );
        assert.equal(certificate.subarray(0, 4).toString('ascii'), 'SSC1');
        const endorsementOffset =
            8 +
            certificate.readUInt32LE(4) +
            bounds.registration.signatureBytes;
        assert.deepEqual(
            Array.from({ length: bounds.quorum }, (_, ordinal) =>
                certificate.readUInt16LE(
                    endorsementOffset +
                        ordinal * (2 + bounds.registration.signatureBytes),
                ),
            ),
            positions
                .filter((position) => !departed.has(position))
                .slice(0, bounds.quorum),
        );
        independentOutcome = (await inBrowser(leftOut, undefined, (chrome) =>
            chrome.evaluate(
                `window.verifyOutcome(${JSON.stringify(organizer.poll)})`,
            ),
        )) as WorkerResult;
        assert.equal(independentOutcome.status, 'completed');
        assert.ok(independentOutcome.status === 'completed');
        assert.equal(independentOutcome.details.hasResult, true);
        assert.deepEqual(independentOutcome.details.identifiers, identifiers);
    }
    if (departureSchedule !== undefined) {
        assert.deepEqual(
            [...departed],
            departureSchedule.departures.map(({ position }) => position),
        );
        // The certified selection holds the first remaining
        // eligible authors' offers, including those of authors
        // that left after offering.
        const selection = await readFile(
            path.join(publicDirectory, 'selection.bin'),
        );
        const fields = tupleFields(selection);
        assert.equal(fields.length, 3);
        const rosterIdentity = Buffer.from(fields[1]).toString('hex');
        const selected = await Promise.all(
            departureSchedule.selectedPositions.map(async (position) => ({
                position,
                bodyIdentity: (
                    await generatedOfferIdentity(publicDirectory, position)
                ).toString('hex'),
            })),
        );
        assert.deepEqual(
            selection,
            encodeSetupSelectionModel(
                participantCount,
                rosterIdentity,
                selected,
            ),
        );
        // Its certificate carries a quorum of distinct endorsers,
        // none of which left before endorsing.
        const certificate = await readFile(
            path.join(publicDirectory, 'setup-certificate.bin'),
        );
        assert.equal(certificate.subarray(0, 4).toString('ascii'), 'SSC1');
        const endorsementOffset =
            8 +
            certificate.readUInt32LE(4) +
            bounds.registration.signatureBytes;
        certificateEndorsers = Array.from(
            { length: bounds.quorum },
            (_, ordinal) =>
                certificate.readUInt16LE(
                    endorsementOffset +
                        ordinal * (2 + bounds.registration.signatureBytes),
                ),
        );
        const unendorsed = departureSchedule.departures
            .filter(
                ({ boundary }) =>
                    boundary === 'before-confirmation' ||
                    boundary === 'before-offer' ||
                    boundary === 'before-selection',
            )
            .map(({ position }) => position);
        assert.equal(new Set(certificateEndorsers).size, bounds.quorum);
        assert.ok(
            certificateEndorsers.every(
                (position) =>
                    position < participantCount &&
                    !unendorsed.includes(position),
            ),
        );
        independentOutcome = (await inBrowser(leftOut, undefined, (chrome) =>
            chrome.evaluate(
                'window.verifyOutcome(' + JSON.stringify(organizer.poll) + ')',
            ),
        )) as WorkerResult;
        assert.ok(independentOutcome.status === 'completed');
        assert.equal(independentOutcome.details.hasResult, true);
        assert.deepEqual(independentOutcome.details.identifiers, identifiers);
    }
    if (publicationFaults) {
        assert.equal(
            publicationRecoveryEvidence.length,
            maximumCorruptParticipantCount > 0 ? 2 : 1,
        );
        assert.equal(
            incompleteResponseEvidence.length,
            maximumCorruptParticipantCount > 0 ? 1 : 0,
        );
        assert.ok(relay.publicationFaultEvidence.length > 0);
        for (const key of [
            'poll',
            'roster',
            'selection',
            'setup-certificate',
            'close-intent',
            'close-proposal',
            'target-vote-0',
            'release-0',
        ])
            assert.ok(
                relay.publicationFaultEvidence.some(
                    (entry) => entry.key === key && entry.changed !== undefined,
                ),
                'Missing genuine-verifier refusal control for ' + key,
            );
        for (const position of positions)
            if (!departed.has(position)) await depart(position);
        independentOutcome = (await inBrowser(leftOut, undefined, (chrome) =>
            chrome.evaluate(
                'window.verifyOutcome(' + JSON.stringify(organizer.poll) + ')',
            ),
        )) as WorkerResult;
        assert.ok(independentOutcome.status === 'completed');
        assert.deepEqual(independentOutcome.details.identifiers, identifiers);
        log.writeEvent({
            eventType: 'participant-publication-candidates-verified',
            details: {
                candidates: relay.publicationFaultEvidence,
                retiredOriginalParticipants: [...departed],
                independentOutcome,
            },
        });
    }
    if (selectionFork) {
        assert.equal(selectionForkEvidence.length, 1);
        independentOutcome = (await inBrowser(leftOut, undefined, (chrome) =>
            chrome.evaluate(
                'window.verifyOutcome(' + JSON.stringify(organizer.poll) + ')',
            ),
        )) as WorkerResult;
        assert.ok(independentOutcome.status === 'completed');
        assert.deepEqual(independentOutcome.details.identifiers, identifiers);
    }
    await writeFile(
        path.join(log.runDirectoryPath, 'result.json'),
        JSON.stringify(
            {
                participantCount,
                optionCount,
                mode,
                sequential,
                recovery: measureRecovery,
                ...(measureRecovery
                    ? {
                          interruptions,
                          standaloneMilliseconds,
                      }
                    : {}),
                scalar,
                setupDeparture,
                unselectedCheckpoint,
                publicationFaults,
                selectionFork,
                departures,
                ...(departureSchedule !== undefined
                    ? {
                          departureSchedule: departureSchedule.departures,
                          selectedPositions:
                              departureSchedule.selectedPositions,
                          activePositions: positions.filter(
                              (position) => !departed.has(position),
                          ),
                          certificateEndorsers,
                      }
                    : {}),
                ...(selectionFork ? { selectionForkEvidence } : {}),
                ...(publicationFaults
                    ? {
                          publicationFaultEvidence:
                              relay.publicationFaultEvidence,
                          publicationRecoveryEvidence,
                          incompleteResponseEvidence,
                      }
                    : {}),
                ...(setupDeparture
                    ? {
                          departedAfterRoster: 1,
                          ...(participantCount === 7
                              ? { departedAfterOffer: 2 }
                              : {}),
                          cooperativeCorruptPositions: [2],
                          activePositions: positions.filter(
                              (position) => !departed.has(position),
                          ),
                          selectedPositions: positions
                              .filter(
                                  (position) =>
                                      position < eligibleContributorCount &&
                                      position !== 1,
                              )
                              .slice(0, setupContributorCount),
                      }
                    : {}),
                ...(unselectedCheckpoint
                    ? {
                          cooperativeCorruptPositions: [2],
                          activePositions: [0, 1, 2, 3],
                          selectedPositions: [0, 2],
                          unselectedCheckpointEvidence,
                          interruptions,
                      }
                    : {}),
                independentOutcome,
                setupDiscoveryFaults,
                poll: organizer.poll,
                registrationBodyDigests: plainRecordIds,
                runtimeIdentity: runtime.identity.runtime,
                peakProcessTreeBytes: peaks,
                identifiers,
                topCount,
                profiled: cpuProfiling,
                memoryPressures,
                transfers,
                sampledResources,
                workflow: measureWorkflow
                    ? summarizeParticipantWorkflow(
                          ordinaryOperations,
                          participantCount,
                          sequential,
                          ordinaryBootstraps,
                      )
                    : null,
            },
            null,
            2,
        ) + '\n',
        { flag: 'wx' },
    );
};
