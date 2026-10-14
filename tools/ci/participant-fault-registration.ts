import assert from 'node:assert/strict';

import { type ParticipantCohort } from '#tools/ci/participant-browser-cohort.js';

export const registerFaultCohort = async (
    cohort: Pick<
        ParticipantCohort,
        | 'participantCount'
        | 'join'
        | 'leftOut'
        | 'organizer'
        | 'request'
        | 'interrupt'
        | 'run'
        | 'positions'
        | 'honest'
        | 'endBrowser'
        | 'expectStatus'
        | 'hexadecimal'
        | 'definition'
        | 'definitionSignature'
    >,
) => {
    const {
        participantCount,
        join,
        leftOut,
        organizer,
        request,
        interrupt,
        run,
        positions,
        honest,
        endBrowser,
        expectStatus,
        hexadecimal,
        definition,
        definitionSignature,
    } = cohort;
    // One more registrant joins beside the participants, and the
    // organizer leaves it out of the roster.
    const [joined, leftOutRegistration] = await Promise.all([
        Promise.all(
            Array.from({ length: participantCount - 1 }, (_unused, index) =>
                join(index + 1, `Participant ${String(index + 1)}`),
            ),
        ),
        join(leftOut, 'Registrant left out'),
    ]);
    const registrationBodyDigests = [organizer, ...joined].map((value) =>
        String(value.registrationBodyDigest),
    );
    // A proposal that also lists the registrant left out exceeds the
    // poll's participant maximum and is refused.
    assert.deepEqual(
        await request(0, 'propose-roster', {
            registrationBodyDigests: [
                ...registrationBodyDigests,
                String(leftOutRegistration.registrationBodyDigest),
            ],
        }),
        { status: 'refused', reason: 'invalid request' },
    );
    // The organizer crashes with its proposal intent, and its next
    // visit verifies the records again and signs the locked proposal
    // deterministically. The last honest participant crashes
    // right after it retains the accepted roster, and its next visit
    // continues from that roster.
    await interrupt(0, 'propose-roster', { registrationBodyDigests }, 2);
    const proposed = await run(0, 'propose-roster', {
        registrationBodyDigests,
    });
    assert.equal(proposed.generation, 3);
    await run(0, 'publish');
    const rosterReplay = [...positions]
        .reverse()
        .find((position) => position > 0 && honest(position));
    assert.ok(rosterReplay !== undefined);
    const accepted = await Promise.all(
        joined.map(async (_details, index) => {
            const position = index + 1;
            if (position !== rosterReplay)
                return run(position, 'accept-roster', {
                    registrationBodyDigests,
                });
            await interrupt(
                position,
                'accept-roster',
                { registrationBodyDigests },
                3,
            );
            return run(position, 'status');
        }),
    );
    for (const details of accepted) assert.equal(details.generation, 3);
    // The registrant left out stays pending when shown the roster
    // and keeps its registration; its browser then ends.
    assert.deepEqual(
        await request(leftOut, 'accept-roster', {
            registrationBodyDigests,
        }),
        {
            status: 'pending',
            cause: 'public input',
            detail: 'The proposal omits this participant.',
        },
    );
    const leftOutStatus = await run(leftOut, 'status');
    assert.equal(leftOutStatus.generation, 1);
    assert.equal(
        leftOutStatus.registrationBodyDigest,
        leftOutRegistration.registrationBodyDigest,
    );
    await endBrowser(leftOut);
    // A second proposal, acceptance or enrollment is refused, and
    // every participant restores its retained state.
    await expectStatus(0, 'propose-roster', 'refused', {
        registrationBodyDigests,
    });
    await expectStatus(1, 'accept-roster', 'refused', {
        registrationBodyDigests,
    });
    // A malformed request is refused; the participant continues
    // below.
    assert.deepEqual(
        await request(1, 'accept-roster', {
            registrationBodyDigests: registrationBodyDigests.map((id) =>
                id.toUpperCase(),
            ),
        }),
        { status: 'refused', reason: 'invalid request' },
    );
    await expectStatus(1, 'create', 'refused', {
        role: 'joiner',
        poll: organizer.poll,
        definition: hexadecimal(definition),
        definitionSignature: hexadecimal(definitionSignature),
        username: 'Participant again',
    });
    return { registrationBodyDigests, leftOutRegistration };
};

export type FaultRegistration = NonNullable<
    Awaited<ReturnType<typeof registerFaultCohort>>
>;
