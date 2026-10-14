import assert from 'node:assert/strict';
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';

import { type ParticipantCohort } from '#tools/ci/participant-browser-cohort.js';
import type { FaultPreparation } from '#tools/ci/participant-fault-preparation.js';
export const closeFaultBallots = async (
    cohort: Pick<
        ParticipantCohort,
        | 'departing'
        | 'depart'
        | 'participantCount'
        | 'mode'
        | 'positions'
        | 'departed'
        | 'noResult'
        | 'minimumTurnout'
        | 'invalidAuthor'
        | 'equivocator'
        | 'omittedVoter'
        | 'honest'
        | 'copyNames'
        | 'copyState'
        | 'ballotScores'
        | 'interrupt'
        | 'loseState'
        | 'run'
        | 'request'
        | 'removeCopy'
        | 'expectStatus'
        | 'bounds'
        | 'publicDirectory'
        | 'views'
        | 'storedRecords'
        | 'outsiders'
    >,
    prepared: Pick<FaultPreparation, 'lateSetup'>,
) => {
    const {
        departing,
        depart,
        participantCount,
        mode,
        positions,
        departed,
        noResult,
        minimumTurnout,
        invalidAuthor,
        equivocator,
        omittedVoter,
        honest,
        copyNames,
        copyState,
        ballotScores,
        interrupt,
        loseState,
        run,
        request,
        removeCopy,
        expectStatus,
        bounds,
        publicDirectory,
        views,
        storedRecords,
        outsiders,
    } = cohort;
    const { lateSetup } = prepared;
    // The departing participant leaves after its preparation.
    if (departing !== undefined) await depart(departing);
    // Every participant that did not depart signs one ballot, the late
    // ones after the others. A result closes with every ballot but the
    // last on time, or with every ballot when a position equivocates.
    // A no-result target has one valid on-time ballot fewer than the
    // minimum turnout, from the honest positions just before the last,
    // and the invalid author's ballot on time, which would meet the
    // turnout if it counted. An empty close has no ballot at all. A
    // signed ballot refuses other scores and is only delivered again.
    const lastPosition = participantCount - 1;
    const ballotAuthors =
        mode === 'empty'
            ? []
            : positions.filter((position) => !departed.has(position));
    const onTimeCount =
        mode === 'empty'
            ? 0
            : noResult
              ? minimumTurnout - 1 + (invalidAuthor === undefined ? 0 : 1)
              : equivocator === undefined
                ? ballotAuthors.length - 1
                : ballotAuthors.length;
    // The equivocator's slot is conflicting, so no ballot of it counts,
    // the omitted ballot is in no slot, and the invalid author's slot
    // is usable but its ballot invalid.
    const usableCount =
        onTimeCount -
        (equivocator === undefined ? 0 : 1) -
        (omittedVoter === undefined ? 0 : 1);
    const validCount = usableCount - (invalidAuthor === undefined ? 0 : 1);
    assert.ok(
        validCount >= (mode === 'empty' ? 0 : 1) &&
            validCount >= minimumTurnout !== noResult,
    );
    const onTimeBallots =
        mode === 'no-result'
            ? [
                  ...(invalidAuthor === undefined ? [] : [invalidAuthor]),
                  ...positions
                      .filter(
                          (position) =>
                              position !== lastPosition && honest(position),
                      )
                      .slice(1 - minimumTurnout),
              ].sort((left, right) => left - right)
            : ballotAuthors.slice(0, onTimeCount);
    assert.equal(onTimeBallots.length, onTimeCount);
    const lateBallots = ballotAuthors.filter(
        (position) => !onTimeBallots.includes(position),
    );
    // Before its ballot the equivocator's private state is copied
    // twice, and each copy acts in its own browser at the same origin.
    // All three correlated publications complete. Explicit discovery
    // views below choose which signed envelope each recipient sees.
    const ballotDiscoveryName = (author: number) =>
        'ballot-' + String(author) + '/submission.bin';
    if (equivocator !== undefined) {
        for (const copy of copyNames) await copyState(equivocator, copy);
    }
    // The first honest authors halt between them at every ballot
    // generation: after the attempt lock, with the seed retained,
    // with the body and signing intent retained, and with the
    // signed ballot before its delivery.
    const ballotHalts = new Map(
        ballotAuthors
            .filter(honest)
            .slice(0, 3)
            .map(
                (position, index) =>
                    [position, [[13, 17], [14], [15]][index]] as const,
            ),
    );
    const signBallot = async (position: number) => {
        const scores = ballotScores(position);
        // A signed ballot is only delivered again. A copy of the state
        // with the retained body loses a body record and stops.
        const halts = ballotHalts.get(position) ?? [];
        for (const generation of halts) {
            await interrupt(position, 'cast-ballot', { scores }, generation);
            if (generation === 15)
                await loseState(position, 'ballot', 'cast-ballot');
        }
        assert.equal(
            (
                await run(
                    position,
                    'cast-ballot',
                    halts.includes(17) ? {} : { scores },
                )
            ).generation,
            17,
        );
    };
    // Each copy of the equivocator's state signs other scores.
    const signCopy = async (copy: string) => {
        assert.ok(equivocator !== undefined);
        const result = await request(
            equivocator,
            'cast-ballot',
            {
                scores: ballotScores(
                    participantCount + copyNames.indexOf(copy),
                ),
            },
            copy,
        );
        assert.ok(result.status === 'completed', JSON.stringify(result));
        assert.equal(result.details.generation, 17);
    };
    // The on-time ballots and the conflicting copy's are signed
    // together, and the late ones, the late copy's among them, only
    // once every on-time ballot is signed, so that each late ballot is
    // timed after every on-time one.
    const copyBallots = (copy: string) =>
        equivocator === undefined ? [] : [signCopy(copy)];
    await Promise.all([
        ...onTimeBallots.map(signBallot),
        ...copyBallots('conflicting'),
    ]);
    await Promise.all([...lateBallots.map(signBallot), ...copyBallots('late')]);
    if (equivocator !== undefined) {
        // Retransmit the original bytes and restore the diagnostic
        // inspection index before deleting the corrupt copies.
        assert.equal((await run(equivocator, 'cast-ballot')).generation, 17);
        for (const copy of copyNames) await removeCopy(copy);
    }
    if (ballotAuthors.includes(0)) {
        await expectStatus(0, 'cast-ballot', 'refused', {
            scores: ballotScores(1),
        });
        assert.equal((await run(0, 'cast-ballot')).generation, 17);
    }
    const ballotBounds = bounds.ballot;
    // The envelope ends with the ballot time, the body length and the body
    // identity.
    const bodyLengthOffset = ballotBounds.envelopeBytes - 64 - 8;
    const ballotTimeOffset = bodyLengthOffset - 8;
    // The diagnostic index names an original submission for fixture inspection.
    const submissionDirectory = async (author: number) =>
        path.join(
            publicDirectory,
            'ballot-' + String(author),
            (
                await readFile(
                    path.join(publicDirectory, ballotDiscoveryName(author)),
                )
            ).toString('hex'),
        );
    for (const position of ballotAuthors) {
        const directory = await submissionDirectory(position);
        const envelope = await readFile(path.join(directory, 'envelope.bin'));
        const body = await stat(path.join(directory, 'body.bin'));
        assert.equal(envelope.length, ballotBounds.envelopeBytes);
        assert.equal(
            envelope.readBigUInt64LE(bodyLengthOffset),
            BigInt(body.size),
        );
        assert.ok(
            body.size >= ballotBounds.minimumBodyBytes &&
                body.size <= ballotBounds.maximumBodyBytes,
        );
        assert.equal(
            (await stat(path.join(directory, 'signature.bin'))).size,
            bounds.registration.signatureBytes,
        );
    }
    // The organizer's close time is the latest on-time ballot time, so
    // a strictly later ballot is late: the intent lock retires it
    // wherever it was delivered, and no response lists it. An empty
    // close takes the time the organizer closes.
    const ballotTime = async (directory: string) =>
        Number(
            (
                await readFile(path.join(directory, 'envelope.bin'))
            ).readBigUInt64LE(ballotTimeOffset),
        );
    const ballotTimes = new Map(
        await Promise.all(
            ballotAuthors.map(
                async (position) =>
                    [
                        position,
                        await ballotTime(await submissionDirectory(position)),
                    ] as const,
            ),
        ),
    );
    // The equivocator's directory also holds one ballot from each
    // copy, the late copy's timed last.
    const equivocation =
        equivocator === undefined
            ? undefined
            : await (async () => {
                  const directory = path.join(
                      publicDirectory,
                      'ballot-' + String(equivocator),
                  );
                  const original = path.basename(
                      await submissionDirectory(equivocator),
                  );
                  const copied = await Promise.all(
                      (await readdir(directory))
                          .filter(
                              (entry) =>
                                  /^[0-9a-f]{128}$/u.test(entry) &&
                                  entry !== original,
                          )
                          .map(async (identity) => ({
                              identity,
                              time: await ballotTime(
                                  path.join(directory, identity),
                              ),
                          })),
                  );
                  assert.equal(copied.length, copyNames.length);
                  const [conflicting, late] = copied.sort(
                      (left, right) => left.time - right.time,
                  );
                  return {
                      position: equivocator,
                      original,
                      conflicting,
                      late,
                  };
              })();
    if (equivocation !== undefined)
        for (const view of views)
            view.set(
                ballotDiscoveryName(equivocation.position),
                Buffer.from(equivocation.original, 'hex'),
            );
    const closeTime =
        mode === 'empty'
            ? Date.now()
            : Math.max(
                  ...onTimeBallots.map((position) => {
                      const time = ballotTimes.get(position);
                      assert.ok(time !== undefined);
                      return time;
                  }),
                  ...(equivocation === undefined
                      ? []
                      : [equivocation.conflicting.time]),
              );
    const onTime = (position: number) =>
        (ballotTimes.get(position) ?? Infinity) <= closeTime;
    assert.deepEqual(
        ballotAuthors.filter((position) => !onTime(position)),
        lateBallots,
    );
    if (equivocation !== undefined)
        assert.ok(equivocation.late.time > closeTime);
    const others = (position: number) =>
        positions.filter((other) => other !== position);
    // The given positions that signed a ballot, and the generation a
    // participant's completed ballot or verified setup leaves.
    const cast = (authors: readonly number[]) =>
        authors.filter((author) => ballotAuthors.includes(author));
    // The relay shows the omitted ballot to its author alone.
    const shown = (position: number, authors: readonly number[]) =>
        authors.filter(
            (author) => author !== omittedVoter || position === omittedVoter,
        );
    const beforeClose = mode === 'empty' ? 12 : 17;
    const submissions = (kind: string, authors: readonly number[]) =>
        authors.map((position) => ({ kind, position }));
    // Hide candidate discovery temporarily, preserving any earlier
    // explicit selection or omission when the view is restored.
    const hideBallotDiscovery = (
        position: number,
        authors: readonly number[],
    ) => {
        const hidden = authors.map((author) => {
            const name = ballotDiscoveryName(author);
            return {
                name,
                existed: views[position].has(name),
                value: views[position].get(name),
            };
        });
        for (const { name } of hidden) views[position].set(name, undefined);
        return () => {
            for (const { name, existed, value } of hidden) {
                if (existed) views[position].set(name, value);
                else views[position].delete(name);
            }
        };
    };
    // The relay shows one honest verifier no other author's pointer
    // until it responds, so it holds only its own ballot. Its later
    // target checks must consume every other body from the public
    // source even when other participants reuse custody.
    const publicBodyProbe =
        mode === 'empty'
            ? undefined
            : positions.find(
                  (position) =>
                      position !== 0 &&
                      honest(position) &&
                      !departed.has(position),
              );
    // The probe holds no close record to lose, so the participants
    // that lose state are chosen with the probe last.
    const probeLast = (candidates: number[]) =>
        candidates.sort(
            (left, right) =>
                Number(left === publicBodyProbe) -
                Number(right === publicBodyProbe),
        );
    // The relay serves every other participant none of the omitted
    // ballot's records until the target votes are published.
    const omission: string[] = [];
    if (omittedVoter !== undefined) {
        const directory = await submissionDirectory(omittedVoter);
        omission.push(
            ballotDiscoveryName(omittedVoter),
            ...(await readdir(directory)).map((file) =>
                path
                    .relative(publicDirectory, path.join(directory, file))
                    .split(path.sep)
                    .join('/'),
            ),
        );
        for (const position of others(omittedVoter))
            for (const name of omission) views[position].set(name, undefined);
    }
    // The relay's pointer to the equivocator's ballot names its late
    // copy's ballot to the last participant, and its conflicting
    // copy's to the organizer's first collection.
    const discoveryIdentity = (identity: string) =>
        Buffer.from(identity, 'hex');
    if (equivocation !== undefined)
        views[lastPosition].set(
            ballotDiscoveryName(equivocation.position),
            discoveryIdentity(equivocation.late.identity),
        );
    const restoreProbeDiscovery =
        publicBodyProbe === undefined
            ? () => undefined
            : hideBallotDiscovery(publicBodyProbe, others(publicBodyProbe));
    // Every other participant with its verified setup collects the
    // published ballots, its own first, before any intent exists;
    // with no ballot it collects nothing and commits nothing.
    await Promise.all(
        positions
            .slice(1)
            .filter(
                (position) => position !== lateSetup && !departed.has(position),
            )
            .map(async (position) => {
                const details = await run(position, 'close');
                assert.equal(details.generation, beforeClose);
                assert.deepEqual(details.closeEvents, [
                    ...submissions('own', cast([position])),
                    ...submissions(
                        'held',
                        position === publicBodyProbe
                            ? []
                            : shown(position, cast(others(position))),
                    ),
                ]);
            }),
    );
    // The organizer's first collection sees only the pointer to the
    // equivocator's conflicting copy.
    const equivocatorHeld =
        equivocation === undefined ? [] : [equivocation.position];
    if (equivocation !== undefined) {
        views[0].set(
            ballotDiscoveryName(equivocation.position),
            discoveryIdentity(equivocation.conflicting.identity),
        );
        const restoreOrganizerDiscovery = hideBallotDiscovery(
            0,
            others(0).filter((author) => author !== equivocation.position),
        );
        const collected = await run(0, 'close');
        restoreOrganizerDiscovery();
        views[0].set(
            ballotDiscoveryName(equivocation.position),
            discoveryIdentity(equivocation.original),
        );
        assert.equal(collected.generation, 17);
        assert.deepEqual(collected.closeEvents, [
            ...submissions('own', [0]),
            ...submissions('held', equivocatorHeld),
        ]);
    }
    // The relay hides one honest on-time ballot's pointer from the
    // organizer until its proposal exists, so the organizer opens the
    // close and locks its own intent without that ballot and learns
    // its envelope only from the responses. It then holds both of the
    // equivocator's on-time envelopes. With no ballot it learns
    // nothing.
    const withheld = shown(0, others(0)).find(
        (position) =>
            onTime(position) && position !== equivocator && honest(position),
    );
    assert.equal(withheld === undefined, mode === 'empty');
    const withheldList = withheld === undefined ? [] : [withheld];
    const restoreWithheldDiscovery = hideBallotDiscovery(0, withheldList);
    const organizerDeliveries = shown(0, cast(others(0))).filter(
        (position) => position !== withheld,
    );
    await expectStatus(1, 'close', 'refused', { closeTime });
    // The organizer halts with its intent before signing it, and its
    // next visit signs the retained intent without a close time.
    await interrupt(0, 'close', { closeTime }, 18);
    const opened = await run(0, 'close');
    assert.equal(opened.generation, 19);
    const organizerCollected = [
        ...submissions('own', [0].filter(onTime)),
        ...submissions('held', equivocatorHeld),
        ...submissions('held', organizerDeliveries.filter(onTime)),
    ];
    assert.deepEqual(opened.closeEvents, [
        ...organizerCollected,
        { kind: 'lock' },
    ]);
    await expectStatus(0, 'close', 'refused', { closeTime });
    // The last participant's setup arrives only after the organizer's
    // close intent: once the setup is retained, the participant
    // learns that ballot submission closed, locks the intent and can
    // no longer vote.
    if (lateSetup !== undefined) {
        const verified = await run(lateSetup, 'verify-setup');
        assert.equal(verified.generation, 19);
        assert.equal(verified.ballotState, 'could not vote');
        await expectStatus(lateSetup, 'cast-ballot', 'refused', {
            scores: ballotScores(lateSetup),
        });
    }
    // A copy of honest state loses its last close record, or its last
    // data record when it holds no close record, as when every ballot
    // it held was late or none was cast, and stops.
    const closeStore = async (position: number) =>
        (await storedRecords(position, 'close')) > 0 ? 'close' : 'data';
    // Every other participant locks the intent and responds at once.
    // The last participant's lock retires the late ballot it held
    // from the equivocator.
    const heldOnTime = (position: number) =>
        shown(position, others(position)).filter(
            (author) =>
                onTime(author) &&
                !(author === equivocator && position === lastPosition),
        );
    // The omitted voter responds only after the proposal exists.
    const responders = positions
        .slice(1)
        .filter((position) => !outsiders.includes(position));
    // The first two other honest responders halt after locking the
    // intent and with their response intent.
    const responseHalts = new Map(
        probeLast(responders.filter(honest))
            .slice(0, 2)
            .map((position, index) => [position, [19, 20][index]]),
    );
    // They collect nothing more: the public body probe still sees no
    // other pointer, and the last participant still sees only the
    // equivocator's late copy.
    await Promise.all(
        responders.map(async (position) => {
            const halt = responseHalts.get(position);
            if (halt !== undefined)
                await interrupt(position, 'close', {}, halt);
            if (halt === 19)
                await loseState(position, await closeStore(position), 'close');
            const details = await run(position, 'close');
            assert.equal(details.generation, 21);
            assert.deepEqual(details.closeEvents, [
                ...submissions('own', [position].filter(onTime)),
                ...submissions(
                    'held',
                    position === publicBodyProbe ? [] : heldOnTime(position),
                ),
                { kind: 'lock' },
            ]);
        }),
    );
    restoreProbeDiscovery();
    if (equivocation !== undefined)
        views[lastPosition].delete(ballotDiscoveryName(equivocation.position));
    // The lock ended the ballot window, so a participant without a
    // ballot starts none.
    if (mode === 'empty')
        await expectStatus(1, 'cast-ballot', 'refused', {
            scores: ballotScores(1),
        });
    // The organizer takes the other responses, fetches the body they
    // list that it lacks, responds and proposes. It halts with its
    // signed response and retained proposal intent, and with its
    // signed proposal before delivering it. The withheld pointer keeps
    // it from collecting that ballot itself, so it fetches only the
    // listed body.
    await interrupt(0, 'close', {}, 21);
    await interrupt(0, 'close', {}, 22);
    // Its next visit restores the completed close without replaying
    // the log, so the retained events name no author or responder;
    // the published proposal below names the responses it took.
    const concluded = await run(0, 'close');
    assert.equal(concluded.generation, 22);
    const responseEvents = (concluded.closeEvents as { kind: string }[]).filter(
        (event) => event.kind === 'response',
    );
    assert.ok(responseEvents.length >= bounds.quorum - 1);
    assert.ok(responseEvents.length <= responders.length);
    assert.deepEqual(
        (concluded.closeEvents as { kind: string }[]).filter(
            (event) => event.kind !== 'response',
        ),
        [
            ...organizerCollected,
            { kind: 'lock' },
            ...submissions('held', withheldList),
        ].map(({ kind }) => ({ kind })),
    );
    restoreWithheldDiscovery();
    // Completed close work is only delivered again.
    assert.equal((await run(1, 'close')).generation, 21);
    assert.equal((await run(0, 'close')).generation, 22);
    // The omitted voter then locks the intent and responds, listing
    // its own ballot, which no response in the proposal lists.
    if (omittedVoter !== undefined) {
        const details = await run(omittedVoter, 'close');
        assert.equal(details.generation, 21);
        assert.deepEqual(details.closeEvents, [
            ...submissions('own', [omittedVoter].filter(onTime)),
            ...submissions('held', heldOnTime(omittedVoter)),
            { kind: 'lock' },
        ]);
    }
    const closeBounds = bounds.close;
    const signatureBytes = bounds.registration.signatureBytes;
    const closeDirectory = path.join(publicDirectory, 'close');
    const intent = await readFile(path.join(closeDirectory, 'intent.bin'));
    assert.equal(
        intent.length,
        4 + closeBounds.intentBodyBytes + signatureBytes,
    );
    assert.equal(
        intent.readBigUInt64LE(4 + closeBounds.intentBodyBytes - 8),
        BigInt(closeTime),
    );
    for (const position of positions.filter(
        (responder) => !departed.has(responder),
    )) {
        const response = await readFile(
            path.join(closeDirectory, `response-${String(position)}.bin`),
        );
        const length = response.readUInt32LE(0);
        assert.ok(
            length >= closeBounds.minimumResponseBodyBytes &&
                length <= closeBounds.maximumResponseBodyBytes,
        );
        assert.equal(response.length, 4 + length + signatureBytes);
        // The listing holds exactly the on-time ballots its responder
        // holds: the organizer lists both of the equivocator's
        // on-time envelopes, which makes its slot conflicting, the
        // last participant, which held only the late one, none, and
        // only the omitted voter its own ballot.
        const listed = [];
        for (
            let offset = 4 + closeBounds.minimumResponseBodyBytes;
            offset < 4 + length;
            offset += 66
        )
            listed.push(response.readUInt16LE(offset));
        assert.deepEqual(
            listed,
            shown(position, positions.filter(onTime))
                .filter(
                    (author) =>
                        position !== publicBodyProbe || author === position,
                )
                .flatMap((author) =>
                    author !== equivocator
                        ? [author]
                        : position === 0
                          ? [author, author]
                          : position === lastPosition
                            ? []
                            : [author],
                ),
        );
    }
    // The proposal names the organizer's response and the first other
    // responses it took, up to the close quorum.
    const proposal = await readFile(path.join(closeDirectory, 'proposal.bin'));
    assert.equal(
        proposal.length,
        4 + closeBounds.proposalBodyBytes + signatureBytes,
    );
    const named = [];
    for (let index = 0; index < bounds.quorum; index++)
        named.push(
            proposal.readUInt16LE(
                4 +
                    closeBounds.proposalBodyBytes -
                    (bounds.quorum - index) * 66,
            ),
        );
    assert.deepEqual(named, [0, ...responders].slice(0, bounds.quorum));
    return {
        probeLast,
        onTime,
        ballotAuthors,
        closeStore,
        usableCount,
        validCount,
        omission,
        signatureBytes,
        onTimeBallots,
        publicBodyProbe,
        submissionDirectory,
        closeTime,
        lateBallots,
        equivocation,
    };
};

export type FaultClose = NonNullable<
    Awaited<ReturnType<typeof closeFaultBallots>>
>;
