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
import {
    type ParticipantCohort,
    requireScalarMemory,
} from '#tools/ci/participant-browser-cohort.js';
import { generatedOfferIdentity } from '#tools/ci/participant-browser-public-records.js';
import { completeRoster } from '#tools/ci/participant-browser-roster-completion.js';
import { summarizeParticipantWorkflow } from '#tools/ci/participant-workflow-measurements.js';

// Carries one roster through each stage once, with the recovery,
// departure, setup and publication schedules the options select.
export const runSingleRoster = async (cohort: ParticipantCohort) => {
    const {
        participantCount,
        optionCount,
        mode,
        profiling,
        scalar,
        setupDeparture,
        unselectedCheckpoint,
        selectionFork,
        memoryPressure,
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
                [0, 'sign-target', targetPhase.intent],
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
            Array.from({ length: bounds.close.quorum }, (_, ordinal) =>
                certificate.readUInt16LE(
                    endorsementOffset +
                        ordinal * (2 + bounds.registration.signatureBytes),
                ),
            ),
            positions
                .filter((position) => !departed.has(position))
                .slice(0, bounds.close.quorum),
        );
        independentOutcome = (await inBrowser(leftOut, undefined, (chrome) =>
            chrome.evaluate(
                `window.verifyOutcome(${JSON.stringify(organizer.poll)})`,
            ),
        )) as WorkerResult;
        assert.equal(independentOutcome.status, 'completed');
        assert.ok(independentOutcome.status === 'completed');
        assert.equal(independentOutcome.details.encrypted, true);
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
            { length: bounds.close.quorum },
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
        assert.equal(new Set(certificateEndorsers).size, bounds.close.quorum);
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
        assert.equal(independentOutcome.details.encrypted, true);
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
                profiled: profiling,
                memoryPressures,
                transfers,
                sampledResources,
                unmeasured: [
                    measureWorkflow
                        ? 'Exact within-call allocation of organizer close work; explicit visit durations are conservative upper bounds'
                        : 'Productive-visit traversal for this fault schedule',
                    'Exact transient browser and JavaScript memory peaks between samples',
                    'HTTP headers and link-layer transfer overhead',
                    'Human delays between visits',
                    'Physical-device performance and power use',
                ],
                workflow: measureWorkflow
                    ? summarizeParticipantWorkflow(
                          ordinaryOperations,
                          participantCount,
                          sequential,
                          ordinaryBootstraps,
                      )
                    : null,
                scope: [
                    setupDeparture
                        ? "Original registrations fix one roster; honest eligible position one disappears immediately after roster publication, before confirmation or contribution. Position two announces an invalid body identity before its valid original offer; the organizer stays pending without consuming selection authority and later accepts the valid offer behind that hint. In the seven-participant case, position two also loses its entire profile after completing its offer but before selection, so the remaining quorum certifies setup containing the departed author's original contribution. Every surviving original member votes, closes, certifies the target and releases the verified result. Original positions and thresholds remain unchanged; the diagnostic fields identify the selected and active sets. This is the named external Chrome schedule, not a general adversarial-scheduling proof."
                        : unselectedCheckpoint
                          ? 'All four original participants remain available, with cooperative corrupt position two and no permanent departure in the real branch. Honest eligible position one retains its genuine phase-five checkpoint while positions zero and two are selected. It endorses without completing its own offer, preserves the original nested own state and encrypted records, then retires them only on certified setup activation and casts a ballot and releases. An isolated damaged-checkpoint copy stops before activation or publication; the healthy original continues. Diagnostic fingerprints stay separate from protocol authority. This is desktop development evidence, not phone qualification.'
                          : 'Browser registration, roster confirmation, signed clear contribution offers, quorum setup selection and verification, ballots, close responses, target votes, release shares and the combined result of one roster, with the recorded stage and recovery schedule in the maintained participant runtime in external Chrome.',
                    ...(measureRecovery
                        ? [
                              'Original participant zero loses its worker and browser at the retained contribution checkpoint, ballot body, target signing intent and release body. Each following visit restores the original state. Workflow totals include every interrupted attempt, cold startup and completed recovery; the recorded cuts define this recovery workload. A fresh public reader verifies the outcome after every original participant departs, with its startup and work reported separately.',
                          ]
                        : []),
                    ...(departureSchedule !== undefined
                        ? [
                              'Members other than the organizer, as many as the profile tolerates, leave for good at the scheduled boundaries between the roster’s publication and the target vote, each losing its browser and private state. Members leaving before their offer never offer, and selected authors leave after offering. The remaining quorum completes setup certification, close, target certification, release and the combined result without them, counting the ballots of departed voters, and a fresh standalone reader verifies the same outcome. This is one named schedule, not every departure combination.',
                          ]
                        : []),
                    ...(profiling
                        ? [
                              'Chrome recorded the CPU samples of every operation, which slows it.',
                          ]
                        : []),
                    ...(selectionFork
                        ? [
                              'A corrupt organizer signs two selections from the same original credential in separate private copies. Honest position one keeps its one losing endorsement, accepts the certified selection of positions zero and two, and completes its ballot and release without issuing another endorsement. A fresh public reader verifies the same outcome.',
                          ]
                        : []),
                    ...(memoryPressure
                        ? [
                              'The second contributor first contributed in a browser that caps each WebAssembly memory below what its contribution needs, which left it pending, and its next visit completed the contribution.',
                          ]
                        : []),
                    ...(publicationFaults
                        ? [
                              'Every publication key receives an empty and a corrupted candidate before the genuine carrier. The organizer retains a signed ballot whose publication is refused and closes without retrying that ballot. Its closure publishes the exact required body, and a fresh standalone verifier retrieves the result after every original participant has departed.',
                          ]
                        : []),
                ].join(' '),
            },
            null,
            2,
        ) + '\n',
        { flag: 'wx' },
    );
};
