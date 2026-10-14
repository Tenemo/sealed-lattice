import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import {
    completedClosePhase,
    targetPhase,
} from '#packages/sdk/src/participant/worker/storage/root-generation.js';
import { type ParticipantCohort } from '#tools/ci/participant-browser-cohort.js';
import type { FaultClose } from '#tools/ci/participant-fault-close.js';
export const releaseFaultTarget = async (
    cohort: Pick<
        ParticipantCohort,
        | 'positions'
        | 'maximumCorruptParticipantCount'
        | 'participantCount'
        | 'departed'
        | 'equivocator'
        | 'invalidAuthor'
        | 'honest'
        | 'omittedVoter'
        | 'interrupt'
        | 'loseState'
        | 'run'
        | 'bounds'
        | 'publicDirectory'
        | 'views'
        | 'depart'
        | 'noResult'
        | 'request'
        | 'headGeneration'
        | 'endBrowser'
        | 'recoveryOperations'
        | 'expectStatus'
    >,
    closed: Pick<
        FaultClose,
        | 'probeLast'
        | 'onTime'
        | 'ballotAuthors'
        | 'closeStore'
        | 'usableCount'
        | 'validCount'
        | 'omission'
        | 'signatureBytes'
    >,
) => {
    const {
        positions,
        maximumCorruptParticipantCount,
        participantCount,
        departed,
        equivocator,
        invalidAuthor,
        honest,
        omittedVoter,
        interrupt,
        loseState,
        run,
        bounds,
        publicDirectory,
        views,
        depart,
        noResult,
        request,
        headGeneration,
        endBrowser,
        recoveryOperations,
        expectStatus,
    } = cohort;
    const {
        probeLast,
        onTime,
        ballotAuthors,
        closeStore,
        usableCount,
        validCount,
        omission,
        signatureBytes,
    } = closed;
    // The profile's inventory certificate threshold is also the close
    // quorum. The last corrupt positions beyond it among the
    // participants that did not depart sign no target vote; they
    // release later from their completed close.
    const nonvoters = positions.slice(
        1 +
            maximumCorruptParticipantCount -
            (participantCount - departed.size - bounds.quorum),
        1 + maximumCorruptParticipantCount,
    );
    const voters = positions.filter(
        (position) => !nonvoters.includes(position) && !departed.has(position),
    );
    assert.equal(voters.length, bounds.quorum);
    // Every voter verifies the barrier, classifies each usable
    // ballot, evaluates the target and signs its vote. Every on-time
    // ballot but the equivocator's and the omitted one is usable,
    // every usable submission but the invalid author's is valid, the
    // omitted voter's ballot is reported omitted, a late one late,
    // and a participant without a ballot has none cast.
    // The equivocator and the invalid author are nonvoters.
    assert.ok(
        [equivocator, invalidAuthor].every(
            (position) =>
                position === undefined || nonvoters.includes(position),
        ),
    );
    // The first other honest voter halts with its target intent, and
    // the organizer with its signed vote before delivering it, so its
    // next visit only delivers the vote.
    const targetHalts = new Map([
        ...probeLast(
            voters.filter((position) => position !== 0 && honest(position)),
        )
            .slice(0, 1)
            .map((position) => [position, 23] as const),
        [0, 24] as const,
    ]);
    // A conflicting slot leaves the equivocator's ballot omitted.
    const ballotInclusion = (position: number) =>
        position === omittedVoter || position === equivocator
            ? 'omitted'
            : onTime(position)
              ? 'included'
              : ballotAuthors.includes(position)
                ? 'late'
                : 'not cast';
    await Promise.all(
        voters.map(async (position) => {
            const halt = targetHalts.get(position);
            if (halt !== undefined)
                await interrupt(position, 'sign-target', {}, halt);
            if (halt === 23)
                await loseState(
                    position,
                    await closeStore(position),
                    'sign-target',
                );
            const details = await run(position, 'sign-target');
            assert.equal(details.generation, 24);
            // The signing state retains the own ballot's status, so
            // a visit that only delivers the vote reports it too.
            assert.equal(details.ballotInclusion, ballotInclusion(position));
            if (halt === 24) return;
            assert.equal(details.usableSubmissions, usableCount);
            assert.equal(details.acceptedBallots, validCount);
        }),
    );
    // A signed vote is only delivered again, and every later operation
    // reports the retained status.
    const repeated = await run(voters[voters.length - 1], 'sign-target');
    assert.equal(repeated.generation, 24);
    assert.equal(
        repeated.ballotInclusion,
        ballotInclusion(voters[voters.length - 1]),
    );
    assert.equal(
        (await run(voters[voters.length - 1], 'status')).ballotInclusion,
        ballotInclusion(voters[voters.length - 1]),
    );
    const targetBounds = bounds.target;
    const completionDirectory = path.join(publicDirectory, 'completion');
    const target = await readFile(path.join(completionDirectory, 'target.bin'));
    assert.ok(
        target.length > 0 && target.length <= targetBounds.maximumBodyBytes,
    );
    // Every vote names its signer and one target identity, and no
    // other participant published one.
    const silent = positions.filter((position) => !voters.includes(position));
    for (const position of silent)
        await assert.rejects(
            stat(
                path.join(
                    completionDirectory,
                    `target-vote-${String(position)}.bin`,
                ),
            ),
            { code: 'ENOENT' },
        );
    const targetIdentities = new Set<string>();
    for (const position of voters) {
        const vote = await readFile(
            path.join(
                completionDirectory,
                `target-vote-${String(position)}.bin`,
            ),
        );
        assert.equal(vote.length, targetBounds.votePacketBytes);
        assert.equal(vote.readUInt16LE(0), position);
        targetIdentities.add(vote.subarray(2, 66).toString('hex'));
    }
    assert.equal(targetIdentities.size, 1);
    // Every vote is published, so the certificate exists, and the
    // relay serves the omitted ballot again. The organizer then
    // departs before any release exists: its browser ends and its
    // private state is deleted.
    for (const view of views) for (const name of omission) view.delete(name);
    await depart(0);
    const remaining = positions.filter((position) => !departed.has(position));
    const combiningPosition = remaining[remaining.length - 1];
    const releaseBounds = bounds.release;
    const completionFile = (name: string, position: number) =>
        path.join(completionDirectory, name + String(position) + '.bin');
    // A voter releases after its signed target and a nonvoter after
    // its completed close.
    const predecessor = (position: number) =>
        voters.includes(position)
            ? targetPhase.signed
            : completedClosePhase(false);
    let interruption:
        | Readonly<{
              position: number;
              resumedFrom: Readonly<{ generation: number }>;
          }>
        | undefined;
    if (noResult) {
        // The certified target carries no result, so each remaining
        // participant's release certifies it and creates nothing.
        for (const position of remaining) {
            const details = await run(position, 'release');
            assert.equal(details.generation, predecessor(position));
            assert.equal(details.hasResult, false);
            assert.equal(details.predecessor, undefined);
            assert.equal(details.resumedFrom, undefined);
            // A nonvoter reads its status from the certified target.
            assert.equal(details.ballotInclusion, ballotInclusion(position));
        }
    } else {
        // Every remaining participant certifies the target from the
        // published votes, retains the seed of its release
        // randomness, and generates and signs its release share. The
        // first remaining voter's browser closes while it generates
        // its share from the retained seed, and its next visit
        // generates it again from that seed.
        const interruptedPosition = remaining.find((position) =>
            voters.includes(position),
        );
        assert.ok(interruptedPosition !== undefined);
        const interruptRelease = async () => {
            const interrupted = request(interruptedPosition, 'release');
            for (;;) {
                const outcome = await Promise.race([
                    interrupted.then(
                        (result) => ({ result }),
                        (error: unknown) => ({
                            error:
                                error instanceof Error
                                    ? error.message
                                    : String(error),
                        }),
                    ),
                    delay(1000, 'waiting'),
                ]);
                assert.equal(
                    outcome,
                    'waiting',
                    'The release ended before its interruption: ' +
                        JSON.stringify(outcome),
                );
                if ((await headGeneration(interruptedPosition)) === 26) break;
            }
            await endBrowser(interruptedPosition);
            await assert.rejects(interrupted);
            recoveryOperations.set(interruptedPosition, 'release');
            const details = await run(interruptedPosition, 'release');
            assert.equal(details.generation, 29);
            assert.equal(details.hasResult, true);
            assert.equal(
                details.ballotInclusion,
                ballotInclusion(interruptedPosition),
            );
            assert.equal(details.predecessor, predecessor(interruptedPosition));
            const resumedFrom = details.resumedFrom as {
                generation: number;
            };
            assert.equal(resumedFrom.generation, 26);
            return resumedFrom;
        };
        const [resumedFrom] = await Promise.all([
            interruptRelease(),
            ...remaining
                .filter(
                    (position) =>
                        position !== interruptedPosition &&
                        position !== combiningPosition,
                )
                .map(async (position) => {
                    const details = await run(position, 'release');
                    assert.equal(details.generation, 29);
                    assert.equal(details.resumedFrom, undefined);
                    assert.equal(details.hasResult, true);
                    assert.equal(
                        details.ballotInclusion,
                        ballotInclusion(position),
                    );
                    assert.equal(details.predecessor, predecessor(position));
                }),
        ]);
        interruption = { position: interruptedPosition, resumedFrom };
        // The combining participant halts at every generation after
        // its target lock, the last with its signed release before
        // delivery, which its next visit only delivers.
        for (const generation of [26, 27, 29])
            await interrupt(combiningPosition, 'release', {}, generation);
        const delivered = await run(combiningPosition, 'release');
        assert.equal(delivered.generation, 29);
        assert.equal(delivered.hasResult, undefined);
        // A release after the completed close spent the target
        // purpose, and its lock retains the own ballot's status.
        for (const position of nonvoters) {
            await expectStatus(position, 'sign-target', 'refused');
            assert.equal(
                (await run(position, 'status')).ballotInclusion,
                ballotInclusion(position),
            );
        }
        // A signed release is only delivered again.
        const rereleased = await run(combiningPosition, 'release');
        assert.equal(rereleased.generation, 29);
        assert.equal(rereleased.hasResult, undefined);
        for (const position of remaining) {
            const body = await stat(completionFile('release-', position));
            assert.ok(
                body.size >= releaseBounds.minimumBodyBytes &&
                    body.size <= releaseBounds.maximumBodyBytes,
            );
            const packet = await readFile(
                completionFile('release-envelope-', position),
            );
            assert.equal(
                packet.length,
                releaseBounds.envelopeBytes + signatureBytes,
            );
            // The envelope ends with the body length and identity.
            assert.equal(
                Number(
                    packet.readBigUInt64LE(
                        releaseBounds.envelopeBytes - 64 - 8,
                    ),
                ),
                body.size,
            );
        }
    }
    // No departed participant released, and nobody releases for a
    // no-result target.
    for (const position of noResult ? positions : departed)
        for (const name of ['release-', 'release-envelope-'])
            await assert.rejects(stat(completionFile(name, position)), {
                code: 'ENOENT',
            });
    return {
        remaining,
        combiningPosition,
        voters,
        completionFile,
        silent,
        releaseBounds,
        nonvoters,
        interruption,
    };
};

export type FaultRelease = NonNullable<
    Awaited<ReturnType<typeof releaseFaultTarget>>
>;
