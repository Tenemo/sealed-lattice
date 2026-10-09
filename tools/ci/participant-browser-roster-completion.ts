import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';

import {
    decodeCandidateManifest,
    encodeCandidateManifest,
} from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';
import { tupleFields } from '#packages/sdk/src/participant/worker/shared/bytes.js';
import { targetPhase } from '#packages/sdk/src/participant/worker/storage/root-generation.js';
import type {
    Member,
    ParticipantCohort,
} from '#tools/ci/participant-browser-cohort.js';
import type { ParticipantDepartureBoundary } from '#tools/ci/participant-browser-options.js';
import { generatedOfferIdentity } from '#tools/ci/participant-browser-public-records.js';
import type { CheckpointCustodyObservation } from '#tools/ci/participant-preparation-storage.js';

// Completes one roster from its proposal to its combined
// result, every member acting as soon as its inputs exist.
// Every member casts a counted ballot and releases. Ordinary
// measurement also gives every member target and result work;
// fault schedules retain quorum target voters and one combiner.
export const completeRoster = async (
    cohort: ParticipantCohort,
    members: readonly Member[],
    registrationBodyDigests: readonly string[],
    scores: readonly (readonly number[])[],
    absent?: number,
) => {
    const {
        participantCount,
        unselectedCheckpoint,
        selectionFork,
        memoryPressure,
        publicationFaults,
        sequential,
        measureRecovery,
        log,
        browsers,
        measureWorkflow,
        measuredStages,
        maximumCorruptParticipantCount,
        setupContributorCount,
        bounds,
        eligibleContributorCount,
        departureSchedule,
        publicDirectory,
        relay,
        views,
        origin,
        copyBrowser,
        departed,
        depart,
        inBrowser,
        request,
        positions,
        headGeneration,
        retainedHead,
        pressure,
        copyState,
        removeCopy,
        interrupt,
        interruptPreparation,
        act,
        rankedIdentifiers,
        setupDiscoveryFaults,
        publicationRecoveryEvidence,
        incompleteResponseEvidence,
        unselectedCheckpointEvidence,
        selectionForkEvidence,
        inspectCheckpoint,
        sameOwnCheckpoint,
    } = cohort;
    const organizing = members[0];
    const incompleteResponder =
        publicationFaults && maximumCorruptParticipantCount > 0 ? 1 : undefined;
    let active = members.flatMap((member, position) =>
        position === absent ? [] : [{ member, position }],
    );
    let accepting = active.filter(({ position }) => position !== 0);
    // Scheduled members leave for good at their boundary; the
    // ballots of those leaving after casting still count.
    const departedVoters: number[] = [];
    const departAt = async (boundary: ParticipantDepartureBoundary) => {
        for (const { position } of departureSchedule?.departures.filter(
            (value) => value.boundary === boundary,
        ) ?? []) {
            await depart(members[position].origin);
            active = active.filter((value) => value.position !== position);
            accepting = accepting.filter(
                (value) => value.position !== position,
            );
            if (
                boundary === 'before-close-response' ||
                boundary === 'before-target-vote'
            )
                departedVoters.push(position);
            log.writeEvent({
                eventType: 'participant-departed',
                details: { position, boundary },
            });
        }
    };
    const markStage = (stages: number[], actors = active) => {
        if (measureWorkflow)
            for (const { member } of actors)
                measuredStages[member.origin] = [...stages];
    };
    const each = async (
        actors: typeof active,
        action: (member: (typeof active)[number]) => Promise<void>,
    ) => {
        if (sequential) {
            for (const member of actors) await action(member);
        } else await Promise.all(actors.map(action));
    };
    const contributing = active
        .filter(
            ({ position }) =>
                position < eligibleContributorCount &&
                !(unselectedCheckpoint && position === 1) &&
                (departureSchedule === undefined ||
                    departureSchedule.selectedPositions.includes(position)),
        )
        .slice(
            0,
            selectionFork ? eligibleContributorCount : setupContributorCount,
        );
    assert.equal(
        contributing.length,
        selectionFork ? eligibleContributorCount : setupContributorCount,
    );
    const confirmAndContribute = async (value: (typeof active)[number]) => {
        assert.equal((await act(value.member, 'confirm')).generation, 4);
        if (contributing.some(({ position }) => position === value.position)) {
            if (measureRecovery && value.position === 0) {
                assert.equal(value.member.copy, undefined);
                await interruptPreparation(value.member.origin, 'contribute', {
                    kind: 'contribution',
                    phase: 5,
                });
            }
            assert.equal((await act(value.member, 'contribute')).generation, 4);
        }
    };
    markStage([1]);
    assert.equal(
        (
            await act(organizing, 'propose-roster', {
                registrationBodyDigests,
            })
        ).generation,
        3,
    );
    await act(organizing, 'publish');
    if (absent !== undefined) await depart(members[absent].origin);
    await departAt('before-confirmation');
    if (measureWorkflow) {
        await confirmAndContribute(active[0]);
        await each(accepting, async (value) => {
            assert.equal(
                (
                    await act(value.member, 'accept-roster', {
                        registrationBodyDigests,
                    })
                ).generation,
                3,
            );
            await confirmAndContribute(value);
        });
    } else {
        for (const details of await Promise.all(
            accepting.map(({ member }) =>
                act(member, 'accept-roster', {
                    registrationBodyDigests,
                }),
            ),
        ))
            assert.equal(details.generation, 3);
        await Promise.all(
            active.map(async ({ member }) => {
                assert.equal((await act(member, 'confirm')).generation, 4);
            }),
        );
    }
    await departAt('before-offer');
    let originalCheckpoint: CheckpointCustodyObservation | undefined;
    if (unselectedCheckpoint) {
        assert.deepEqual(
            active.map(({ position }) => position),
            [0, 1, 2, 3],
        );
        assert.deepEqual(
            contributing.map(({ position }) => position),
            [0, 2],
        );
        await interruptPreparation(1, 'contribute', {
            kind: 'contribution',
            phase: 5,
        });
        originalCheckpoint = await inspectCheckpoint('original checkpoint');
        assert.equal(originalCheckpoint.generation, 4);
        assert.equal(originalCheckpoint.phase, 5);
        assert.equal(originalCheckpoint.endorsement, null);
        assert.ok(
            originalCheckpoint.checkpointRecords > 0 &&
                originalCheckpoint.contributionRecords > 0,
        );
        assert.match(
            originalCheckpoint.ownJournalSha512 ?? '',
            /^[0-9a-f]{128}$/u,
        );
        assert.equal(
            await stat(path.join(publicDirectory, 'contribution-1')).catch(
                () => undefined,
            ),
            undefined,
        );
    }
    if (memoryPressure)
        await pressure(contributing[1].member.origin, 'contribute');
    const contribute = async (member: Member) =>
        assert.equal((await act(member, 'contribute')).generation, 4);
    if (absent !== undefined) {
        assert.deepEqual(
            contributing.map(({ position }) => position),
            positions
                .filter(
                    (position) =>
                        position < eligibleContributorCount &&
                        position !== absent,
                )
                .slice(0, setupContributorCount),
        );
        await contribute(contributing[0].member);
        const badIdentity = 'a5'.repeat(64);
        const announced = await inBrowser(2, undefined, (chrome) =>
            chrome.evaluate(
                `fetch('/offers/2', { method: 'POST', body: new Uint8Array(64).fill(165) }).then(response => response.status)`,
            ),
        );
        assert.equal(announced, 204);
        const before = await retainedHead(0);
        assert.equal(before.generation, 4);
        const pending = await request(0, 'select-setup');
        assert.deepEqual(pending, {
            status: 'pending',
            cause: 'public input',
            detail: 'Too few complete eligible contribution offers are available.',
        });
        assert.deepEqual(
            await retainedHead(0),
            before,
            'An invalid discovery hint consumed the selection intent.',
        );
        assert.equal(
            await stat(path.join(publicDirectory, 'selection.bin')).catch(
                () => undefined,
            ),
            undefined,
        );
        await Promise.all(
            contributing.slice(1).map(({ member }) => contribute(member)),
        );
        const announcements = await inBrowser(2, undefined, (chrome) =>
            chrome.evaluate(`fetch('/offers/2?offset=0').then(async response => {
                        if (!response.ok) throw new Error('Offer announcements unavailable.');
                        const bytes = new Uint8Array(await response.arrayBuffer());
                        const view = new DataView(bytes.buffer);
                        const count = view.getUint32(8, true);
                        if (view.getBigUint64(0, true) !== 2n || bytes.length !== 12 + count * 64) throw new Error('Malformed discovery page.');
                        return Array.from({ length: count }, (_, index) => Array.from(bytes.subarray(12 + index * 64, 12 + (index + 1) * 64), value => value.toString(16).padStart(2, '0')).join(''));
                    })`),
        );
        assert.deepEqual(announcements, [
            badIdentity,
            (await generatedOfferIdentity(publicDirectory, 2)).toString('hex'),
        ]);
        const fault = {
            position: 2,
            invalidAnnouncementFirst: true,
            laterValidAnnouncementPreserved: true,
            result: pending,
            originalSelectionIntentUnused: true,
        };
        setupDiscoveryFaults.push(fault);
        log.writeEvent({
            eventType: 'participant-offer-discovery-fault',
            details: fault,
        });
    } else if (!measureWorkflow)
        await Promise.all(contributing.map(({ member }) => contribute(member)));
    await departAt('before-selection');
    if (absent !== undefined && maximumCorruptParticipantCount === 2) {
        // The original signed offer remains a selected input after
        // its author loses its entire profile, before selection.
        await depart(members[2].origin);
        active = active.filter(({ position }) => position !== 2);
        accepting = accepting.filter(({ position }) => position !== 2);
        assert.equal(departed.size, maximumCorruptParticipantCount);
        assert.equal(
            active.length,
            participantCount - maximumCorruptParticipantCount,
        );
        log.writeEvent({
            eventType: 'participant-departed-after-offer',
            details: {
                position: 2,
                originalOffer: (
                    await generatedOfferIdentity(publicDirectory, 2)
                ).toString('hex'),
            },
        });
    }
    markStage([2]);
    if (selectionFork) {
        const copy = 'losing-selection';
        await copyState(0, copy);
        try {
            await act({ origin: 0, copy }, 'select-setup');
            const losingBody = await readFile(
                path.join(publicDirectory, 'selection.bin'),
            );
            await act(active[1].member, 'endorse-setup');
            const originalEndorsement = await readFile(
                path.join(publicDirectory, 'selection-endorsement-1.bin'),
            );
            const hidden =
                'contribution-1/' +
                (await generatedOfferIdentity(publicDirectory, 1)).toString(
                    'hex',
                ) +
                '/offer.bin';
            views[0].set(hidden, undefined);
            try {
                await act(organizing, 'select-setup');
            } finally {
                views[0].delete(hidden);
            }
            const winningBody = await readFile(
                path.join(publicDirectory, 'selection.bin'),
            );
            const winningSignature = await readFile(
                path.join(publicDirectory, 'selection-signature.bin'),
            );
            assert.notDeepEqual(winningBody, losingBody);
            const selectedPositions = (body: Uint8Array) => {
                const fields = tupleFields(body);
                const entries = Buffer.from(fields[2]);
                return Array.from(
                    { length: entries.readUInt32LE(4) },
                    (_, index) => entries.readUInt16LE(8 + index * 66),
                );
            };
            assert.deepEqual(selectedPositions(losingBody), [0, 1]);
            assert.deepEqual(selectedPositions(winningBody), [0, 2]);
            for (const position of [2, 3, 1]) {
                const before =
                    position === 1 ? await retainedHead(position) : undefined;
                views[position].set('selection.bin', winningBody);
                views[position].set(
                    'selection-signature.bin',
                    winningSignature,
                );
                try {
                    await act(active[position].member, 'endorse-setup');
                } finally {
                    views[position].delete('selection.bin');
                    views[position].delete('selection-signature.bin');
                }
                if (position === 1)
                    assert.deepEqual(await retainedHead(position), before);
            }
            assert.deepEqual(
                await readFile(
                    path.join(publicDirectory, 'selection-endorsement-1.bin'),
                ),
                originalEndorsement,
            );
            const evidence = {
                corruptOrganizer: 0,
                losingEndorser: 1,
                losingPositions: selectedPositions(losingBody),
                winningPositions: selectedPositions(winningBody),
                originalEndorsementRetained: true,
            };
            selectionForkEvidence.push(evidence);
            log.writeEvent({
                eventType: 'participant-losing-endorsement-retained',
                details: evidence,
            });
        } finally {
            await removeCopy(copy);
        }
    } else {
        assert.equal((await act(organizing, 'select-setup')).generation, 4);
        await each(accepting, async ({ member }) => {
            assert.equal((await act(member, 'endorse-setup')).generation, 4);
        });
    }
    await departAt('before-setup-verification');
    if (unselectedCheckpoint) {
        assert.ok(originalCheckpoint);
        assert.ok(relay);
        const endorsed = await inspectCheckpoint(
            'endorsed with unused checkpoint',
        );
        assert.equal(endorsed.generation, 4);
        assert.equal(endorsed.endorsement, 'signed');
        sameOwnCheckpoint(originalCheckpoint, endorsed);
        assert.equal(
            await stat(path.join(publicDirectory, 'contribution-1')).catch(
                () => undefined,
            ),
            undefined,
        );
        const copy = 'damaged-unselected-checkpoint';
        await copyState(1, copy);
        try {
            const before = await retainedHead(1, copy);
            const damaged = await inspectCheckpoint(
                'damaged isolated checkpoint copy',
                copy,
                true,
            );
            sameOwnCheckpoint(originalCheckpoint, damaged);
            assert.ok(damaged.damagedRecord);
            assert.notEqual(
                damaged.damagedRecord.beforeSha512,
                damaged.damagedRecord.afterSha512,
            );
            const attempts = relay.publicationAttempts[1];
            const rejected = await request(1, 'verify-setup', {}, copy);
            assert.ok(
                rejected.status === 'stopped' &&
                    rejected.stopPersistence === 'confirmed',
                JSON.stringify(rejected),
            );
            assert.deepEqual(
                await retainedHead(1, copy),
                before,
                'Damaged activation replaced the original preparation root.',
            );
            assert.equal(
                relay.publicationAttempts[1],
                attempts,
                'Damaged checkpoint activation attempted a publication.',
            );
            await browsers.crash(copyBrowser(copy));
            assert.deepEqual(await request(1, 'status', {}, copy), {
                status: 'stopped',
                detail: 'Missing or inconsistent participant authority.',
                stopPersistence: 'confirmed',
            });
            assert.equal(relay.publicationAttempts[1], attempts);
            const fault = {
                stage: 'damaged checkpoint activation refused',
                position: 1,
                result: rejected,
                publicationAttempts: 0,
            };
            unselectedCheckpointEvidence.push(fault);
            log.writeEvent({
                eventType: 'participant-unselected-checkpoint-fault',
                details: fault,
            });
        } finally {
            await removeCopy(copy);
        }
        const healthy = await inspectCheckpoint(
            'healthy original before activation',
        );
        sameOwnCheckpoint(originalCheckpoint, healthy);
        assert.equal(healthy.endorsement, 'signed');
    }
    const castBallot = async ({
        member,
        position,
    }: (typeof active)[number]) => {
        if (
            publicationFaults &&
            (position === 0 || position === incompleteResponder)
        ) {
            assert.ok(relay);
            const key = 'ballot-' + String(position);
            relay.refusedKeys.add(key);
            try {
                const pending = await request(
                    member.origin,
                    'cast-ballot',
                    { scores: scores[position] },
                    member.copy,
                );
                assert.equal(pending.status, 'pending');
                const head = await retainedHead(member.origin, member.copy);
                assert.equal(head.generation, 17);
                assert.equal(
                    await stat(
                        path.join(publicDirectory, key + '/submission.bin'),
                    ).catch(() => undefined),
                    undefined,
                );
                const evidence = {
                    position,
                    stage: 'signed ballot without completed publication',
                    result: pending,
                    generation: head.generation,
                };
                publicationRecoveryEvidence.push(evidence);
                log.writeEvent({
                    eventType: 'participant-publication-interruption',
                    details: evidence,
                });
            } finally {
                relay.refusedKeys.delete(key);
            }
        } else {
            if (measureRecovery && position === 0)
                await interrupt(
                    member.origin,
                    'cast-ballot',
                    { scores: scores[position] },
                    15,
                );
            assert.equal(
                (
                    await act(member, 'cast-ballot', {
                        scores: scores[position],
                    })
                ).generation,
                17,
            );
        }
    };
    markStage([3]);
    await each(active, async ({ member, position }) => {
        const verified = await act(member, 'verify-setup');
        assert.equal(verified.generation, 12);
        assert.equal(verified.ballotState, 'open');
        if (measureWorkflow) await castBallot({ member, position });
    });
    if (unselectedCheckpoint) {
        const retired = await inspectCheckpoint(
            'certified setup retired unused checkpoint',
        );
        assert.equal(retired.generation, 12);
        assert.equal(retired.phase, null);
        assert.equal(retired.ownJournalSha512, null);
        assert.equal(retired.endorsement, null);
        assert.equal(retired.contributionRecords, 0);
        assert.equal(retired.checkpointRecords, 0);
        assert.equal(
            await stat(path.join(publicDirectory, 'contribution-1')).catch(
                () => undefined,
            ),
            undefined,
        );
    }
    if (!measureWorkflow) await Promise.all(active.map(castBallot));
    // A close collects every other participant's published ballot
    // with its body.
    markStage([4]);
    const authors = active.map(({ position }) => position);
    await departAt('before-close-response');
    const collectsEvery = (position: number) => [
        { kind: 'own', position },
        ...authors
            .filter(
                (author) =>
                    author !== position &&
                    (!publicationFaults ||
                        (author !== 0 && author !== incompleteResponder)),
            )
            .map((author) => ({ kind: 'held', position: author })),
    ];
    await Promise.all(
        accepting.map(async ({ member, position }) => {
            const collected = await act(member, 'close');
            assert.equal(collected.generation, 17);
            assert.deepEqual(collected.closeEvents, collectsEvery(position));
        }),
    );
    const opened = await act(organizing, 'close', {
        closeTime: Date.now(),
    });
    assert.equal(opened.generation, 19);
    assert.deepEqual(opened.closeEvents, [
        ...collectsEvery(0),
        { kind: 'lock' },
    ]);
    await Promise.all(
        accepting.map(async ({ member, position }) => {
            if (position === incompleteResponder) {
                assert.ok(relay);
                const key = 'close-response-' + String(position);
                relay.refusedKeys.add(key);
                try {
                    const pending = await request(
                        member.origin,
                        'close',
                        {},
                        member.copy,
                    );
                    assert.equal(pending.status, 'pending');
                    assert.equal(
                        await headGeneration(member.origin, member.copy),
                        21,
                    );
                } finally {
                    relay.refusedKeys.delete(key);
                }
                const complete = relay.refusedCandidates.get(key);
                assert.ok(complete);
                const original = decodeCandidateManifest(complete);
                const files = original.files.filter(
                    (file) =>
                        file.name === 'response.bin' ||
                        file.name === 'submissions.bin',
                );
                assert.equal(files.length, 2);
                assert.ok(original.files.length > files.length);
                // A corrupt sender publishes its real signed response
                // and envelopes, withholding every body reference.
                const carrier = encodeCandidateManifest({ files });
                const published = await fetch(
                    origin(position) + '/candidates/' + key,
                    {
                        method: 'POST',
                        body: new Uint8Array(carrier),
                    },
                );
                assert.equal(published.status, 200);
                await published.arrayBuffer();
                return;
            }
            assert.equal((await act(member, 'close')).generation, 21);
        }),
    );
    if (incompleteResponder !== undefined) {
        await depart(members[incompleteResponder].origin);
        active = active.filter(
            ({ position }) => position !== incompleteResponder,
        );
    }
    await departAt('before-target-vote');
    markStage([4, 5], [active[0]]);
    const concluded = await act(organizing, 'close');
    assert.equal(concluded.generation, 22);
    if (incompleteResponder !== undefined) {
        const receivedResponses = (
            concluded.closeEvents as { kind: string }[]
        ).filter((event) => event.kind === 'response').length;
        assert.equal(receivedResponses, bounds.close.quorum);
        const proposal = await readFile(
            path.join(publicDirectory, 'close/proposal.bin'),
        );
        assert.equal(
            proposal.length,
            4 +
                bounds.close.proposalBodyBytes +
                bounds.registration.signatureBytes,
        );
        const proposalResponders = Array.from(
            { length: bounds.close.quorum },
            (_, ordinal) =>
                proposal.readUInt16LE(
                    4 +
                        bounds.close.proposalBodyBytes -
                        (bounds.close.quorum - ordinal) * 66,
                ),
        );
        assert.deepEqual(
            proposalResponders,
            active
                .slice(0, bounds.close.quorum)
                .map(({ position }) => position),
        );
        const evidence = {
            unavailableResponder: incompleteResponder,
            receivedResponses,
            proposalResponders,
        };
        incompleteResponseEvidence.push(evidence);
        log.writeEvent({
            eventType: 'participant-incomplete-close-response',
            details: evidence,
        });
    }
    markStage([5]);
    await each(
        measureWorkflow ? active : active.slice(0, bounds.close.quorum),
        async ({ member, position }) => {
            if (measureRecovery && position === 0)
                await interrupt(
                    member.origin,
                    'sign-target',
                    {},
                    targetPhase.intent,
                );
            const voted = await act(member, 'sign-target');
            assert.equal(voted.generation, 24);
            assert.equal(voted.ballotInclusion, 'included');
            assert.equal(
                voted.usableSubmissions,
                active.length + departedVoters.length,
            );
            assert.equal(
                voted.acceptedBallots,
                active.length + departedVoters.length,
            );
        },
    );
    markStage([6]);
    await each(active, async ({ member, position }) => {
        if (measureRecovery && position === 0)
            await interrupt(member.origin, 'release', {}, 27);
        const details = await act(member, 'release');
        assert.equal(details.generation, 29);
        assert.equal(details.encrypted, true);
    });
    markStage([7]);
    const expected = rankedIdentifiers([
        ...active.map(({ position }) => scores[position]),
        ...departedVoters.map((position) => scores[position]),
    ]);
    await each(
        measureWorkflow ? active : [active[active.length - 1]],
        async ({ member }) => {
            const combined = await act(member, 'compute-result');
            assert.equal(combined.encrypted, true);
            assert.deepEqual(combined.identifiers, expected);
        },
    );
    return expected;
};
