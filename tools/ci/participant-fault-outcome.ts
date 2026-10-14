import assert from 'node:assert/strict';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import {
    decodeCandidateManifest,
    decodeCandidatePage,
    decodeCandidateReceipt,
} from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';
import type { WorkerResult } from '#packages/sdk/src/participant/worker/runtime/worker-messages.js';
import {
    closureBodyFile,
    closureSubmissionFile,
} from '#packages/sdk/src/participant/worker/stages/close/close-records.js';
import {
    evaluatedTargetName,
    namespacedName,
} from '#packages/sdk/src/participant/worker/storage/database.js';
import { type ParticipantCohort } from '#tools/ci/participant-browser-cohort.js';
import {
    foreignFamilies,
    foreignRecordView,
} from '#tools/ci/participant-browser-public-records.js';
import {
    type ViewedRecord,
    participantDatabase,
    participantNamespace,
} from '#tools/ci/participant-browser-relay.js';
import {
    databaseScript,
    operationMilliseconds,
    requireScalarMemory,
} from '#tools/ci/participant-cohort-state.js';
import type { FaultClose } from '#tools/ci/participant-fault-close.js';
import type { FaultPreparation } from '#tools/ci/participant-fault-preparation.js';
import type { FaultRegistration } from '#tools/ci/participant-fault-registration.js';
import type { FaultRelease } from '#tools/ci/participant-fault-release.js';
export const verifyFaultOutcome = async (
    cohort: Pick<
        ParticipantCohort,
        | 'optionCount'
        | 'positions'
        | 'equivocator'
        | 'omittedVoter'
        | 'ballotScores'
        | 'topCount'
        | 'honest'
        | 'origin'
        | 'leftOut'
        | 'log'
        | 'noResult'
        | 'departed'
        | 'releaseThreshold'
        | 'publicDirectory'
        | 'invalidAuthor'
        | 'mode'
        | 'foreign'
        | 'organizer'
        | 'probeUnread'
        | 'probe'
        | 'run'
        | 'candidateReads'
        | 'inBrowser'
        | 'deliveredRecords'
        | 'request'
        | 'scalar'
        | 'departing'
        | 'participantCount'
        | 'runtime'
        | 'corruptClient'
        | 'peaks'
        | 'copyPeaks'
        | 'minimumBallotAuthor'
        | 'interruptions'
        | 'stateLosses'
    >,
    registered: Pick<
        FaultRegistration,
        'registrationBodyDigests' | 'leftOutRegistration'
    >,
    prepared: Pick<
        FaultPreparation,
        | 'lateSetup'
        | 'setupPublicationFaults'
        | 'selectionReadbackFaults'
        | 'selectedProofFaults'
    >,
    closed: Pick<
        FaultClose,
        | 'onTime'
        | 'onTimeBallots'
        | 'publicBodyProbe'
        | 'submissionDirectory'
        | 'closeTime'
        | 'lateBallots'
        | 'equivocation'
    >,
    released: Pick<
        FaultRelease,
        | 'remaining'
        | 'combiningPosition'
        | 'voters'
        | 'completionFile'
        | 'silent'
        | 'releaseBounds'
        | 'nonvoters'
        | 'interruption'
    >,
) => {
    const {
        optionCount,
        positions,
        equivocator,
        omittedVoter,
        ballotScores,
        topCount,
        honest,
        origin,
        leftOut,
        log,
        noResult,
        departed,
        releaseThreshold,
        publicDirectory,
        invalidAuthor,
        mode,
        foreign,
        organizer,
        probeUnread,
        probe,
        run,
        candidateReads,
        inBrowser,
        deliveredRecords,
        request,
        scalar,
        departing,
        participantCount,
        runtime,
        corruptClient,
        peaks,
        copyPeaks,
        minimumBallotAuthor,
        interruptions,
        stateLosses,
    } = cohort;
    const { registrationBodyDigests, leftOutRegistration } = registered;
    const {
        lateSetup,
        setupPublicationFaults,
        selectionReadbackFaults,
        selectedProofFaults,
    } = prepared;
    const {
        onTime,
        onTimeBallots,
        publicBodyProbe,
        submissionDirectory,
        closeTime,
        lateBallots,
        equivocation,
    } = closed;
    const {
        remaining,
        combiningPosition,
        voters,
        completionFile,
        silent,
        releaseBounds,
        nonvoters,
        interruption,
    } = released;
    // The last remaining participant combines the published shares
    // into the requested prefix of the ranking of the on-time ballots'
    // score totals, ties to the lower option, or finds that the
    // certified target carries no result. The equivocator's ballots
    // and the omitted ballot are not counted. The departed organizer's
    // share is absent, so the first share it tries is unavailable, and
    // the lowest remaining shares include a nonvoter's when one
    // exists and the interrupted voter's.
    const totals = Array.from({ length: optionCount }, (_unused, option) =>
        positions
            .filter(
                (position) =>
                    onTime(position) &&
                    position !== equivocator &&
                    position !== omittedVoter,
            )
            .reduce(
                (total, position) => total + ballotScores(position)[option],
                0,
            ),
    );
    const expectedResult = Array.from(
        { length: optionCount },
        (_unused, option) => option,
    )
        .sort((left, right) => totals[right] - totals[left] || left - right)
        .slice(0, topCount)
        .map((option) => `option-${String(option)}`);
    // Meanwhile a malicious relay shows each other remaining honest
    // participant forged records in its own view. Each view would
    // complete the work only if a forgery counted, so its participant
    // stays pending. One view hides the second voter's vote behind the
    // last voter's vote relabeled with that position, and replays the
    // last voter's vote in every slot without a vote. Another replays the
    // combining participant's share in every departed slot, alters
    // the first remaining participant's body, and relabels that share
    // for each other remaining slot but the last release threshold
    // minus one.
    const probes = remaining.filter(
        (position) => position !== combiningPosition && honest(position),
    );
    const voteProbe = probes[0];
    const shareProbe = probes[probes.length - 1];
    const publicName = (name: string, position: number) =>
        'completion/' + name + String(position) + '.bin';
    const hiddenVoter = voters[1];
    const lastVoter = voters[voters.length - 1];
    assert.notEqual(hiddenVoter, lastVoter);
    const lastVote = await readFile(completionFile('target-vote-', lastVoter));
    const relabeledVote = Buffer.from(lastVote);
    relabeledVote.writeUInt16LE(hiddenVoter, 0);
    // Replay genuine immutable candidates through the public transport.
    // A flat diagnostic path alone cannot populate an empty discovery key.
    const replayCandidate = async (sourceKey: string, targetKey: string) => {
        const base = origin(leftOut);
        const listed = await fetch(
            base + '/candidates/' + sourceKey + '?offset=0',
        );
        assert.equal(listed.status, 200);
        const page = decodeCandidatePage(
            new Uint8Array(await listed.arrayBuffer()),
        );
        assert.ok(page.locators.length > 0);
        const source = await fetch(base + '/candidate/' + page.locators[0]);
        assert.equal(source.status, 200);
        const manifest = new Uint8Array(await source.arrayBuffer());
        decodeCandidateManifest(manifest);
        const posted = await fetch(base + '/candidates/' + targetKey, {
            method: 'POST',
            body: manifest,
        });
        assert.equal(posted.status, 200);
        const receipt = decodeCandidateReceipt(
            new Uint8Array(await posted.arrayBuffer()),
        );
        const readback = await fetch(base + '/candidate/' + receipt.locator);
        assert.equal(readback.status, 200);
        assert.deepEqual(
            new Uint8Array(await readback.arrayBuffer()),
            manifest,
        );
        const discovery = await fetch(
            base +
                '/candidates/' +
                targetKey +
                '?offset=' +
                String(receipt.index),
        );
        assert.equal(discovery.status, 200);
        assert.equal(
            decodeCandidatePage(new Uint8Array(await discovery.arrayBuffer()))
                .locators[0],
            receipt.locator,
        );
        log.writeEvent({
            eventType: 'participant-replayed-candidate',
            details: { sourceKey, targetKey, candidate: receipt.locator },
        });
        return receipt.locator;
    };
    const voteReplays: string[] = [];
    for (const position of silent)
        voteReplays.push(
            await replayCandidate(
                'target-vote-' + String(lastVoter),
                'target-vote-' + String(position),
            ),
        );
    const shareReplays: string[] = [];
    if (!noResult)
        for (const position of departed)
            shareReplays.push(
                await replayCandidate(
                    'release-' + String(combiningPosition),
                    'release-' + String(position),
                ),
            );
    const voteForgeries = new Map([
        [publicName('target-vote-', hiddenVoter), relabeledVote],
        ...silent.map(
            (position) =>
                [publicName('target-vote-', position), lastVote] as const,
        ),
    ]);
    const shareForgeries = new Map<string, Buffer>();
    if (!noResult) {
        const replaced = remaining.slice(
            0,
            remaining.length - (releaseThreshold - 1),
        );
        const envelope = await readFile(
            completionFile('release-envelope-', combiningPosition),
        );
        const body = await readFile(
            completionFile('release-', combiningPosition),
        );
        for (const position of departed) {
            shareForgeries.set(
                publicName('release-envelope-', position),
                envelope,
            );
            shareForgeries.set(publicName('release-', position), body);
        }
        const altered = await readFile(completionFile('release-', replaced[0]));
        altered[altered.length - 1] ^= 1;
        shareForgeries.set(publicName('release-', replaced[0]), altered);
        // The envelope ends with its signer's position, then the body
        // length and identity.
        for (const position of replaced.slice(1)) {
            const relabeled = Buffer.from(envelope);
            relabeled.writeUInt16LE(
                position,
                releaseBounds.envelopeBytes - 64 - 8 - 2,
            );
            shareForgeries.set(
                publicName('release-envelope-', position),
                relabeled,
            );
            shareForgeries.set(publicName('release-', position), body);
        }
    }
    // A third view swaps the first two registrations under each
    // other's body digests. Each is a valid registration for the
    // poll, so only the body digests the retained proposal lists tell
    // them apart, and every visit verifies the setup again from them
    // first.
    const registrationForgeries = new Map<string, Buffer>();
    for (const [from, to] of [
        [0, 1],
        [1, 0],
    ] as const)
        for (const file of await readdir(
            path.join(
                publicDirectory,
                'registration',
                registrationBodyDigests[from],
            ),
        ))
            registrationForgeries.set(
                'registration/' + registrationBodyDigests[to] + '/' + file,
                await readFile(
                    path.join(
                        publicDirectory,
                        'registration',
                        registrationBodyDigests[from],
                        file,
                    ),
                ),
            );
    // With ballots cast, a fourth set of views forges another ballot
    // that the certified target counts, which the vote probe reads
    // from the public records: its body altered or withheld, its
    // submission replaced by another counted author's authentic one,
    // or its signature altered. The refused votes of the first view
    // discard the vote probe's evaluated target, so each of these
    // visits evaluates the target again from the public close records
    // and verifies the close barrier; none of them withdraws or
    // replaces the accepted ballot, and its participant stays pending.
    // When the vote probe's own ballot is the only one counted, the
    // probe reads no counted ballot from the public records, and
    // there is no such view.
    const countedBallots = onTimeBallots.filter(
        (position) =>
            ![equivocator, omittedVoter, invalidAuthor].includes(position),
    );
    const ballotForgeries: {
        forgery: string;
        forgeries: ReadonlyMap<string, ViewedRecord>;
        detail: string;
    }[] = [];
    const forgedAuthor = countedBallots.find(
        (position) => position !== voteProbe,
    );
    const replacingAuthor = countedBallots.find(
        (position) => position !== forgedAuthor,
    );
    if (mode !== 'empty') {
        assert.equal(voteProbe, publicBodyProbe);
        assert.ok(countedBallots.includes(voteProbe));
    }
    if (forgedAuthor !== undefined) {
        assert.ok(replacingAuthor !== undefined);
        const directory = await submissionDirectory(forgedAuthor);
        const replacing = await submissionDirectory(replacingAuthor);
        const submissionIdentity = Buffer.from(path.basename(directory), 'hex');
        const forwardedBody =
            'close/closure/' + closureBodyFile(submissionIdentity);
        const forwardedSubmission =
            'close/closure/' + closureSubmissionFile(submissionIdentity);
        const originalEnvelope = await readFile(
            path.join(directory, 'envelope.bin'),
        );
        const replacingSubmission = Buffer.concat([
            await readFile(path.join(replacing, 'envelope.bin')),
            await readFile(path.join(replacing, 'signature.bin')),
        ]);
        const ballotName = (file: string) =>
            path
                .relative(publicDirectory, path.join(directory, file))
                .split(path.sep)
                .join('/');
        const alteredBody = await readFile(path.join(directory, 'body.bin'));
        alteredBody[alteredBody.length - 1] ^= 1;
        const alteredSignature = await readFile(
            path.join(directory, 'signature.bin'),
        );
        alteredSignature[0] ^= 1;
        ballotForgeries.push(
            {
                forgery: 'altered body',
                forgeries: new Map<string, ViewedRecord>([
                    [ballotName('body.bin'), alteredBody],
                    [forwardedBody, alteredBody],
                ]),
                detail: 'No valid complete candidate is available: close-proposal',
            },
            {
                forgery: 'withheld body',
                forgeries: new Map<string, ViewedRecord>([
                    [ballotName('body.bin'), undefined],
                    [forwardedBody, undefined],
                ]),
                detail: 'No valid complete candidate is available: close-proposal',
            },
            {
                forgery: 'replaced submission',
                forgeries: new Map<string, ViewedRecord>([
                    [forwardedSubmission, replacingSubmission],
                ]),
                detail: 'No valid complete candidate is available: close-proposal',
            },
            {
                forgery: 'altered signature',
                forgeries: new Map<string, ViewedRecord>([
                    [
                        forwardedSubmission,
                        Buffer.concat([originalEnvelope, alteredSignature]),
                    ],
                ]),
                detail: 'No valid complete candidate is available: close-proposal',
            },
        );
    }
    // A fifth set of views serves the other poll's records of one
    // family at a time. The first of them a result visit reads is
    // refused, so its participant stays pending; a family it does not
    // read leaves it the outcome of the relay's own records.
    const foreignProbes: {
        family: string;
        served: number;
        hidden: number;
        detail?: string;
    }[] = [];
    const unreadOutcomes: {
        family: string;
        hasResult: unknown;
        identifiers: unknown;
    }[] = [];
    const probeForeignPoll = async (position: number) => {
        if (foreign === undefined) return;
        assert.notEqual(foreign.poll, organizer.poll);
        for (const { family, pattern, details } of foreignFamilies) {
            // Only a target with a result reads release shares,
            // and only a result run of the other poll released any.
            if (family === 'release shares' && noResult) continue;
            const { view, served } = await foreignRecordView(
                foreign,
                publicDirectory,
                registrationBodyDigests,
                pattern,
            );
            if (family === 'release shares' && served === 0) continue;
            assert.ok(served > 0, `The foreign poll has no ${family}.`);
            let detail: string | undefined;
            if (details === undefined) {
                const { hasResult, identifiers } = await probeUnread(
                    position,
                    view,
                );
                unreadOutcomes.push({ family, hasResult, identifiers });
            } else
                detail = await probe(
                    position,
                    view,
                    details(
                        registrationBodyDigests,
                        foreign.registrationBodyDigests,
                    ),
                );
            foreignProbes.push({
                family,
                served,
                hidden: view.size - served,
                detail,
            });
        }
    };
    const [result] = await Promise.all([
        run(combiningPosition, 'compute-result'),
        ...[...new Set([voteProbe, shareProbe])].map(async (position) => {
            // The vote probe reads the forged ballots before any
            // share view, whose visit retains the target it
            // evaluates.
            if (position === voteProbe) {
                await probe(
                    position,
                    voteForgeries,
                    'The target votes are incomplete.',
                );
                for (const locator of voteReplays)
                    assert.ok(
                        candidateReads[position].has(locator),
                        'The verifier did not encounter the replayed target candidate.',
                    );
                for (const { forgeries, detail } of ballotForgeries)
                    await probe(position, forgeries, detail);
                await probe(
                    position,
                    registrationForgeries,
                    registrationBodyDigests
                        .slice(0, 2)
                        .map(
                            (registrationBodyDigest) =>
                                'No valid complete candidate is available: registration/' +
                                registrationBodyDigest,
                        ),
                );
            }
            if (position === shareProbe && !noResult) {
                await probe(
                    position,
                    shareForgeries,
                    'The release shares are incomplete.',
                );
                for (const locator of shareReplays)
                    assert.ok(
                        candidateReads[position].has(locator),
                        'The verifier did not encounter the replayed release candidate.',
                    );
            }
            if (position === voteProbe) await probeForeignPoll(position);
        }),
    ]);
    assert.equal(result.hasResult, !noResult);
    assert.deepEqual(result.identifiers, noResult ? [] : expectedResult);
    for (const { family, hasResult, identifiers } of unreadOutcomes) {
        assert.equal(hasResult, result.hasResult, family);
        assert.deepEqual(identifiers, result.identifiers, family);
    }
    // None of the forged views stopped its participant or withdrew
    // its ballot: with the relay's own records it combines the same
    // outcome.
    const recovered = await run(voteProbe, 'compute-result');
    assert.equal(recovered.hasResult, result.hasResult);
    assert.deepEqual(recovered.identifiers, result.identifiers);
    // This untrusted public cache is outside the authenticated
    // participant root. A damaged credential-keyed target must be
    // discarded and recomputed from the actual close inputs.
    await inBrowser(voteProbe, undefined, (chrome) =>
        chrome.evaluate(
            databaseScript(
                namespacedName(evaluatedTargetName, participantNamespace),
                `const stored = await result(database.transaction('target').objectStore('target').get(0));
if (!(stored instanceof Blob) || stored.size === 0) throw new Error('No evaluated target cache.');
const tail = new Uint8Array(await stored.slice(-1).arrayBuffer());
tail[0] ^= 1;
const writing = database.transaction('target', 'readwrite');
writing.objectStore('target').put(new Blob([stored.slice(0, -1), tail]), 0);
await completion(writing);`,
            ),
        ),
    );
    deliveredRecords[voteProbe].clear();
    const recomputed = await run(voteProbe, 'compute-result');
    assert.equal(recomputed.hasResult, result.hasResult);
    assert.deepEqual(recomputed.identifiers, result.identifiers);
    assert.ok(
        deliveredRecords[voteProbe].has('close/proposal.bin'),
        'A damaged target cache bypassed recomputation.',
    );
    log.writeEvent({
        eventType: 'participant-damaged-target-recomputed',
        details: { position: voteProbe },
    });
    // Altered retained state stops an honest participant at its next
    // visit, and the stop outlasts restoring the exact bytes. The
    // first byte of its first data record is flipped from its own
    // page, and a second flip restores it.
    const stoppedPosition = probes[0];
    const flipDataRecord = async () =>
        inBrowser(stoppedPosition, undefined, (chrome) =>
            chrome.evaluate(
                databaseScript(
                    participantDatabase,
                    `const cursor = await result(database.transaction('data').objectStore('data').openCursor());
if (cursor === null) throw new Error('No data record.');
const { key, value } = cursor;
const bytes = new Uint8Array(await value.arrayBuffer());
bytes[0] ^= 1;
const writing = database.transaction('data', 'readwrite');
writing.objectStore('data').put(new Blob([bytes]), key);
await completion(writing);
return key;`,
                ),
            ),
        );
    const alteredRecord = await flipDataRecord();
    assert.deepEqual(await request(stoppedPosition, 'status'), {
        status: 'stopped',
        detail: 'A participant data record changed.',
        stopPersistence: 'confirmed',
    });
    assert.deepEqual(await flipDataRecord(), alteredRecord);
    assert.deepEqual(await request(stoppedPosition, 'status'), {
        status: 'stopped',
        detail: 'Missing or inconsistent participant authority.',
        stopPersistence: 'confirmed',
    });
    // The stopped participant, and the registrant left out of the
    // roster, which holds no part in the poll, verify the outcome
    // with the standalone outcome verifier from the poll's identity and the
    // relay's public records alone.
    for (const position of [stoppedPosition, leftOut]) {
        const started = performance.now();
        const deadline = new AbortController();
        const verification = await inBrowser(position, undefined, (chrome) =>
            Promise.race([
                chrome.evaluate(
                    `window.verifyOutcome(${JSON.stringify(organizer.poll)})`,
                ),
                delay(operationMilliseconds, undefined, {
                    signal: deadline.signal,
                }).then(() => {
                    throw new Error('Standalone verification deadline.');
                }),
            ]).finally(() => deadline.abort()),
        );
        const verified = verification as WorkerResult;
        log.writeEvent({
            eventType: 'standalone-verification',
            details: {
                position,
                milliseconds: performance.now() - started,
                ...(verified.status === 'completed'
                    ? { memory: verified.details.memory }
                    : { result: verified }),
            },
        });
        assert.ok(
            verified.status === 'completed',
            'The standalone verification did not complete.',
        );
        assert.equal(verified.details.poll, organizer.poll);
        if (scalar) requireScalarMemory(verified.details);
        assert.equal(verified.details.hasResult, result.hasResult);
        assert.deepEqual(verified.details.identifiers, result.identifiers);
    }
    await writeFile(
        path.join(log.runDirectoryPath, 'result.json'),
        JSON.stringify(
            {
                participantCount,
                optionCount,
                poll: organizer.poll,
                registrationBodyDigests,
                runtimeIdentity: runtime.identity.runtime,
                corruptClient,
                peakProcessTreeBytes: peaks.slice(0, leftOut),
                leftOut: {
                    registrationBodyDigest:
                        leftOutRegistration.registrationBodyDigest,
                    peakProcessTreeBytes: peaks[leftOut],
                },
                copyPeakProcessTreeBytes: Object.fromEntries(copyPeaks),
                closeTime,
                lateBallots,
                minimumBallot: minimumBallotAuthor,
                couldNotVote: lateSetup,
                departedBeforeClose: departing,
                omittedBallot: omittedVoter,
                nonvoters,
                departed: [...departed],
                interrupted: interruption,
                interruptions,
                stateLosses,
                setupPublicationFaults,
                selectionReadbackFaults,
                selectedProofFaults,
                equivocation:
                    equivocation === undefined
                        ? undefined
                        : {
                              position: equivocation.position,
                              conflicting: equivocation.conflicting.identity,
                              late: equivocation.late.identity,
                          },
                forgeries: {
                    votes: {
                        position: voteProbe,
                        paths: [...voteForgeries.keys()],
                    },
                    registrations: {
                        position: voteProbe,
                        paths: [...registrationForgeries.keys()],
                    },
                    ...(forgedAuthor === undefined
                        ? {}
                        : {
                              ballot: {
                                  position: voteProbe,
                                  forgedAuthor,
                                  replacingAuthor,
                                  probes: ballotForgeries.map(
                                      ({ forgery, forgeries, detail }) => ({
                                          forgery,
                                          paths: [...forgeries.keys()],
                                          detail,
                                      }),
                                  ),
                              },
                          }),
                    ...(noResult
                        ? {}
                        : {
                              shares: {
                                  position: shareProbe,
                                  paths: [...shareForgeries.keys()],
                              },
                          }),
                },
                stopped: {
                    position: stoppedPosition,
                    record: alteredRecord,
                },
                foreignPoll:
                    foreign === undefined
                        ? undefined
                        : {
                              run: foreign.run,
                              poll: foreign.poll,
                              position: voteProbe,
                              probes: foreignProbes,
                          },
                topCount,
                scalar,
                result: noResult
                    ? { kind: 'no-result' }
                    : { kind: 'result', identifiers: expectedResult },
            },
            null,
            2,
        ) + '\n',
        { flag: 'wx' },
    );
};
