import assert from 'node:assert/strict';
import { cp, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
    type Member,
    type ParticipantCohort,
    prose,
    secondRosterCopy,
} from '#tools/ci/participant-browser-cohort.js';
import {
    foreignFamilies,
    foreignRecordView,
} from '#tools/ci/participant-browser-public-records.js';
import { completeRoster } from '#tools/ci/participant-browser-roster-completion.js';

// Completes two rosters of one poll beside each other and serves each
// roster's records to a member of the other.
export const runTwoRosters = async (cohort: ParticipantCohort) => {
    const {
        participantCount,
        optionCount,
        mode,
        scalar,
        topCount,
        log,
        maximumCorruptParticipantCount,
        runtime,
        publicDirectory,
        secondRosterDirectory,
        peaks,
        copyPeaks,
        positions,
        copyState,
        ballotScores,
        organizer,
        join,
        act,
        rosterRecordIds,
        probe,
        probeUnread,
    } = cohort;
    // The organizer is corrupt: its private state is copied
    // before it proposes a roster, and the copy proposes a second
    // roster of the same poll to other registrants. The relay
    // serves each roster only its own records and shows the
    // second roster the poll and the organizer's registration.
    // The organizer is each roster's only corrupt member.
    assert.ok(
        maximumCorruptParticipantCount >= 1 &&
            secondRosterDirectory !== undefined,
        'Two rosters need a profile that tolerates the corrupt organizer.',
    );
    await copyState(0, secondRosterCopy);
    for (const name of [
        'poll-definition.bin',
        'poll-signature.bin',
        'registration/' + String(organizer.registrationBodyDigest),
        'transport',
    ])
        await cp(
            path.join(publicDirectory, name),
            path.join(secondRosterDirectory, name),
            { recursive: true, errorOnExist: true, force: false },
        );
    const firstMembers: readonly Member[] = positions.map((position) => ({
        origin: position,
    }));
    const secondMembers: readonly Member[] = positions.map((position) =>
        position === 0
            ? { origin: 0, copy: secondRosterCopy }
            : { origin: participantCount - 1 + position },
    );
    const registrations = await Promise.all(
        [...firstMembers.slice(1), ...secondMembers.slice(1)].map((member) =>
            join(member.origin, `Participant ${String(member.origin)}`),
        ),
    );
    const firstRecordIds = rosterRecordIds(
        registrations.slice(0, participantCount - 1),
    );
    const secondRecordIds = rosterRecordIds(
        registrations.slice(participantCount - 1),
    );
    const [firstIdentifiers, secondIdentifiers] = await Promise.all([
        completeRoster(
            cohort,
            firstMembers,
            firstRecordIds,
            positions.map(ballotScores),
        ),
        completeRoster(
            cohort,
            secondMembers,
            secondRecordIds,
            positions.map((position) =>
                ballotScores(participantCount + position),
            ),
        ),
    ]);
    // A relay view serves the second member of each roster the
    // other roster's records of one family at a time under its
    // own roster's names, the registrations by roster position.
    // The first record of each family its result visit reads is
    // refused, and it stays pending; the other roster's valid
    // registrations of the same poll are refused only as a
    // roster. The families its result visit does not read leave
    // it its roster's outcome, which it also reaches with the
    // relay's own records.
    const crossRosterProbes: {
        origin: number;
        family: string;
        served: number;
        hidden: number;
        detail?: string;
    }[] = [];
    for (const [
        member,
        records,
        registrationBodyDigests,
        other,
        identifiers,
    ] of [
        [
            firstMembers[1],
            publicDirectory,
            firstRecordIds,
            {
                publicDirectory: secondRosterDirectory,
                registrationBodyDigests: secondRecordIds,
                leftOut: undefined,
            },
            firstIdentifiers,
        ],
        [
            secondMembers[1],
            secondRosterDirectory,
            secondRecordIds,
            {
                publicDirectory,
                registrationBodyDigests: firstRecordIds,
                leftOut: undefined,
            },
            secondIdentifiers,
        ],
    ] as const) {
        for (const { family, pattern, details } of foreignFamilies) {
            const { view, served } = await foreignRecordView(
                other,
                records,
                registrationBodyDigests,
                pattern,
            );
            assert.ok(served > 0, `The other roster has no ${family}.`);
            let detail: string | undefined;
            if (details === undefined)
                assert.deepEqual(
                    (await probeUnread(member.origin, view)).identifiers,
                    identifiers,
                );
            else
                detail = await probe(
                    member.origin,
                    view,
                    details(
                        registrationBodyDigests,
                        other.registrationBodyDigests,
                    ),
                );
            crossRosterProbes.push({
                origin: member.origin,
                family,
                served,
                hidden: view.size - served,
                detail,
            });
        }
        assert.deepEqual(
            (await act(member, 'compute-result')).identifiers,
            identifiers,
        );
    }
    // Both rosters retain signed-envelope-before-body ordering.
    const rostersScope = [
        "A corrupt organizer's private state is copied after its registration, and the copy proposes a second roster of the same poll to other registrants under its own path of the organizer's origin, where the relay serves that roster's records. Both rosters, whose only corrupt member is the organizer, complete roster agreement, setup contribution and verification, signed ballots, close responses, target votes, release shares and the combined result in parallel in the maintained participant runtime in external Chrome.",
        `Relay views that serve one roster's ${prose(foreignFamilies.filter(({ details }) => details !== undefined).map(({ family }) => family))} under the other roster's names leave a member of each roster pending, and with the relay's own records it reaches its roster's outcome; its ${prose(foreignFamilies.filter(({ details }) => details === undefined).map(({ family }) => family))}, which a result visit that restores the verified setup and the evaluated target does not read, leave that member its roster's outcome.`,
    ].join(' ');
    await writeFile(
        path.join(log.runDirectoryPath, 'result.json'),
        JSON.stringify(
            {
                participantCount,
                optionCount,
                mode,
                poll: organizer.poll,
                registrationBodyDigests: firstRecordIds,
                runtimeIdentity: runtime.identity.runtime,
                peakProcessTreeBytes: peaks,
                copyPeakProcessTreeBytes: Object.fromEntries(copyPeaks),
                secondRoster: {
                    copy: secondRosterCopy,
                    origins: secondMembers.map((member) => member.origin),
                    registrationBodyDigests: secondRecordIds,
                },
                results: {
                    first: firstIdentifiers,
                    second: secondIdentifiers,
                },
                crossRosterProbes,
                topCount,
                scope: rostersScope,
                scalar,
            },
            null,
            2,
        ) + '\n',
        { flag: 'wx' },
    );
};
