import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
    cp,
    mkdir,
    open,
    readFile,
    readdir,
    stat,
    writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { chunkBytes } from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
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
import { completedClosePhase } from '#packages/sdk/src/participant/worker/stages/close/close-state.js';
import {
    evaluatedTargetName,
    namespacedName,
    setupCacheName,
} from '#packages/sdk/src/participant/worker/storage/database.js';
import { targetPhase } from '#packages/sdk/src/participant/worker/storage/root-generation.js';
import {
    type ParticipantCohort,
    databaseScript,
    operationMilliseconds,
    prose,
    requireScalarMemory,
} from '#tools/ci/participant-browser-cohort.js';
import {
    foreignFamilies,
    foreignRecordView,
    generatedOfferIdentity,
    publicRecordNames,
} from '#tools/ci/participant-browser-public-records.js';
import {
    type ViewedRecord,
    participantDatabase,
    participantNamespace,
} from '#tools/ci/participant-browser-relay.js';

// Runs the complete fault schedule of a result, no-result, empty or
// preparation run.
export const runFaultSchedule = async (cohort: ParticipantCohort) => {
    const {
        participantCount,
        optionCount,
        mode,
        scalar,
        topCount,
        noResult,
        leftOut,
        log,
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
        runtime,
        preparationStorageBundle,
        corruptClient,
        publicDirectory,
        relay,
        views,
        deliveredRecords,
        candidateReads,
        peaks,
        sampledResources,
        copyPeaks,
        origin,
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
        probe,
        probeUnread,
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
    // Eligibility is the fixed redundant pool; selection still uses d.
    const contributors = positions.slice(0, setupContributorCount);
    const noncontributors = positions.slice(eligibleContributorCount);
    const otherMembers = positions.filter(
        (position) => !contributors.includes(position),
    );
    for (const position of positions) {
        const status = await run(position, 'status');
        assert.equal(status.generation, 3);
        assert.equal(status.poll, organizer.poll);
        assert.equal(
            status.isEligibleContributor,
            position < eligibleContributorCount,
        );
        await expectStatus(position, 'contribute', 'refused');
    }
    const setupReplay = [...contributors].reverse().find(honest);
    assert.ok(setupReplay !== undefined);
    await interrupt(setupReplay, 'confirm', {}, 4);
    for (const position of positions)
        assert.equal((await run(position, 'confirm')).generation, 4);
    for (const position of noncontributors)
        await expectStatus(position, 'contribute', 'refused');
    await expectStatus(0, 'verify-setup', 'pending');
    await expectStatus(0, 'select-setup', 'pending');
    await expectStatus(1, 'select-setup', 'refused');
    if (mode === 'preparation') {
        for (const position of positions)
            await inspectSourceCustody(position, 'confirmed roster');
        await refuseLostSource(setupReplay, 'contribute');
    }
    const bodyRecords = bounds.contribution.publicRecords.length;
    await Promise.all(
        contributors.map(async (position) => {
            if (position === setupReplay) {
                await interruptStaged(
                    position,
                    'contribute',
                    4,
                    'checkpoint',
                    1,
                );
                await interruptPreparation(position, 'contribute', {
                    kind: 'contribution',
                    phase: 5,
                });
                // Generic public retransmission must authenticate the
                // same required own checkpoint as other g4 operations.
                await loseState(position, 'checkpoint', 'publish', true);
                await interruptStaged(
                    position,
                    'contribute',
                    4,
                    'contribution',
                    bodyRecords + 1,
                );
                if (mode === 'preparation') {
                    await interruptPadding(position, 'padding');
                    await interruptPadding(position, 'final-slot');
                    const [padding, final] = paddingInterruptions;
                    assert.deepEqual(
                        padding.head,
                        final.head,
                        'Padding replay recreated its continuation intent.',
                    );
                    assert.equal(
                        padding.observation.halt.proofBytes,
                        final.observation.halt.proofBytes,
                    );
                    for (const [
                        index,
                        slot,
                    ] of padding.observation.slots.entries())
                        assert.equal(
                            slot.sha512,
                            final.observation.slots[index].sha512,
                            'Padding replay changed its original proof bytes.',
                        );
                    // Keep the unsigned complete body for authenticated
                    // damaged-padding probes before any offer publication.
                    await interruptPreparation(position, 'contribute', {
                        kind: 'contribution',
                        phase: 7,
                    });
                    return;
                }
                await interruptPreparation(position, 'contribute', {
                    kind: 'contribution',
                    phase: 8,
                });
            }
            assert.equal((await run(position, 'contribute')).generation, 4);
        }),
    );
    const paddingRefusals: Record<string, unknown>[] = [];
    if (mode === 'preparation') {
        assert.ok(preparationStorageBundle && setupReplay !== undefined);
        for (const kind of ['missing', 'nonzero'] as const) {
            const copy = 'padding-' + kind;
            await copyState(setupReplay, copy);
            try {
                const mutation = await inBrowser(setupReplay, copy, (chrome) =>
                    chrome.evaluate(
                        preparationStorageBundle +
                            '\nparticipantPreparationFixture.mutateParticipantPadding(' +
                            JSON.stringify({
                                namespace: participantNamespace,
                                runtimeIdentity: runtime.identity.runtime,
                                moduleDigest: runtime.identity.module,
                                participants: participantCount,
                                options: optionCount,
                                position: setupReplay,
                                kind,
                            }) +
                            ');',
                    ),
                );
                const before: number = relay.publicationAttempts[setupReplay];
                const rejected = await request(
                    setupReplay,
                    'contribute',
                    {},
                    copy,
                );
                assert.deepEqual(rejected, {
                    status: 'stopped',
                    stopPersistence: 'confirmed',
                    detail:
                        kind === 'nonzero'
                            ? 'The private proof padding is nonzero.'
                            : 'The contribution records changed.',
                });
                assert.equal(
                    relay.publicationAttempts[setupReplay],
                    before,
                    'A damaged private proof caused a relay publication attempt.',
                );
                const recorded = {
                    position: setupReplay,
                    kind,
                    mutation,
                    result: rejected,
                    publicationAttempts: 0,
                };
                paddingRefusals.push(recorded);
                log.writeEvent({
                    eventType: 'participant-padding-refusal',
                    details: recorded,
                });
            } finally {
                await removeCopy(copy);
            }
        }
    }
    if (mode === 'preparation') {
        await interruptPreparation(setupReplay, 'contribute', {
            kind: 'contribution',
            phase: 8,
        });
        assert.equal((await run(setupReplay, 'contribute')).generation, 4);
    }
    const offerDirectory = async (position: number) => {
        const identity = await generatedOfferIdentity(
            publicDirectory,
            position,
        );
        assert.equal(identity.length, 64);
        return (
            'contribution-' +
            String(position) +
            '/' +
            identity.toString('hex') +
            '/'
        );
    };
    const replayedOffer = await offerDirectory(setupReplay);
    const replayedEnvelope = await readFile(
        path.join(publicDirectory, replayedOffer, 'offer.bin'),
    );
    const replayedSignature = await readFile(
        path.join(publicDirectory, replayedOffer, 'offer-signature.bin'),
    );
    assert.equal((await run(setupReplay, 'contribute')).generation, 4);
    assert.deepEqual(
        await readFile(path.join(publicDirectory, replayedOffer, 'offer.bin')),
        replayedEnvelope,
    );
    assert.deepEqual(
        await readFile(
            path.join(publicDirectory, replayedOffer, 'offer-signature.bin'),
        ),
        replayedSignature,
    );
    const selectionReadbackFaults: Record<string, unknown>[] = [];
    await interruptPreparation(0, 'select-setup', {
        kind: 'selection',
        phase: 1,
    });
    await interruptPreparation(0, 'select-setup', {
        kind: 'selection',
        phase: 2,
    });
    const selectionHead = await retainedHead(0);
    for (const fault of ['missing', 'changed'] as const) {
        const name = 'selection-signature.bin';
        let changed: Buffer | undefined;
        if (fault === 'changed') {
            changed = await readFile(path.join(publicDirectory, name));
            changed[0] ^= 1;
        }
        views[0].set(name, changed);
        try {
            const result = await request(0, 'select-setup');
            assert.ok(
                result.status === 'pending' && result.cause === 'public input',
                JSON.stringify(result),
            );
            assert.deepEqual(
                await retainedHead(0),
                selectionHead,
                'Failed selection readback changed the original signed selection or created endorsement intent.',
            );
            await assert.rejects(
                stat(path.join(publicDirectory, 'selection-endorsement-0.bin')),
                { code: 'ENOENT' },
            );
            const recorded = {
                fault,
                result,
                signedSelectionHead: selectionHead,
            };
            selectionReadbackFaults.push(recorded);
            log.writeEvent({
                eventType: 'participant-selection-readback-fault',
                details: recorded,
            });
        } finally {
            views[0].delete(name);
        }
    }
    await interruptPreparation(0, 'select-setup', {
        kind: 'selection-readback',
        phase: 1,
    });
    for (const phase of [1, 2])
        await interruptPreparation(0, 'select-setup', {
            kind: 'endorsement',
            phase,
        });
    assert.equal((await run(0, 'select-setup')).generation, 4);
    const selectedBytes = await readFile(
        path.join(publicDirectory, 'selection.bin'),
    );
    assert.equal((await run(0, 'select-setup')).generation, 4);
    assert.deepEqual(
        await readFile(path.join(publicDirectory, 'selection.bin')),
        selectedBytes,
    );
    const endorsementReplay = [...positions].reverse().find(honest);
    assert.ok(endorsementReplay !== undefined);
    const finalOffer = await offerDirectory(
        contributors[contributors.length - 1],
    );
    const selectedProofFaults: Record<string, unknown>[] = [];
    const setupCacheSnapshot = async (position: number) =>
        (await inBrowser(position, undefined, (chrome) =>
            chrome.evaluate(
                databaseScript(
                    namespacedName(setupCacheName, participantNamespace),
                    `if (!database.objectStoreNames.contains('aggregate')) throw new Error('No aggregate cache exists.');
const keys = await result(database.transaction('aggregate').objectStore('aggregate').getAllKeys());
const ordinals = [...new Set(keys.filter((key) => Array.isArray(key) && key.length === 3).map((key) => key[0]))].sort();
return { records: keys.length, ordinals };`,
                ),
            ),
        )) as { records: number; ordinals: number[] };
    if (mode === 'preparation') {
        const proofName = finalOffer + 'proof.bin';
        const faultDirectory = path.join(
            log.artifactDirectoryPath,
            'fault-inputs',
        );
        await mkdir(faultDirectory, { recursive: true });
        const damaged = path.join(faultDirectory, 'late-selected-proof.bin');
        const originalProofBytes = (
            await stat(path.join(publicDirectory, proofName))
        ).size;
        assert.ok(
            originalProofBytes >= bounds.contribution.minimumProofBytes &&
                originalProofBytes <= bounds.contribution.maximumProofBytes,
        );
        await cp(path.join(publicDirectory, proofName), damaged, {
            errorOnExist: true,
            force: false,
        });
        const proof = await open(damaged, 'r+');
        try {
            const length = (await proof.stat()).size;
            assert.equal(length, originalProofBytes);
            const last = Buffer.alloc(1);
            assert.equal(
                (await proof.read(last, 0, 1, length - 1)).bytesRead,
                1,
            );
            last[0] ^= 1;
            await proof.write(last, 0, 1, length - 1);
            await proof.sync();
        } finally {
            await proof.close();
        }
        let proofReads = 0;
        let overwritten: { records: number; ordinals: number[] } | undefined;
        const head = await retainedHead(endorsementReplay);
        const attempts: number = relay.publicationAttempts[endorsementReplay];
        views[endorsementReplay].set(proofName, {
            file: damaged,
            beforeServe: async () => {
                proofReads++;
                if (proofReads === 2) {
                    overwritten = await setupCacheSnapshot(endorsementReplay);
                    assert.ok(overwritten.records > 0);
                    assert.deepEqual(
                        overwritten.ordinals,
                        [setupContributorCount - 1],
                        'The late-proof control did not observe replaced selected-polynomial chunks.',
                    );
                }
            },
        });
        try {
            const result = await request(endorsementReplay, 'endorse-setup');
            assert.ok(
                result.status === 'pending' && result.cause === 'public input',
                JSON.stringify(result),
            );
            assert.ok(overwritten);
            assert.deepEqual(await setupCacheSnapshot(endorsementReplay), {
                records: 0,
                ordinals: [],
            });
            assert.deepEqual(await retainedHead(endorsementReplay), head);
            assert.equal(
                relay.publicationAttempts[endorsementReplay],
                attempts,
            );
            const recorded = {
                position: endorsementReplay,
                proofReads,
                overwritten,
                result,
                publicationAttempts: 0,
            };
            selectedProofFaults.push(recorded);
            log.writeEvent({
                eventType: 'participant-selected-proof-fault',
                details: recorded,
            });
        } finally {
            views[endorsementReplay].delete(proofName);
        }
    }
    await Promise.all(
        positions.map(async (position) => {
            if (position === endorsementReplay) {
                // The first endorsement verifies all clear bodies;
                // later activation may use its retained verification.
                await interruptDelivered(
                    position,
                    'endorse-setup',
                    4,
                    finalOffer + 'offer.bin',
                );
                await interruptPreparation(position, 'endorse-setup', {
                    kind: 'endorsement',
                    phase: 1,
                });
                await interruptPreparation(position, 'endorse-setup', {
                    kind: 'endorsement',
                    phase: 2,
                });
            }
            assert.equal((await run(position, 'endorse-setup')).generation, 4);
            if (mode === 'preparation' && position === endorsementReplay) {
                const cache = await setupCacheSnapshot(position);
                assert.ok(cache.records > 0);
                assert.deepEqual(cache.ordinals, [setupContributorCount - 1]);
                const recorded = {
                    position,
                    stage: 'original selected proof retry',
                    cache,
                };
                selectedProofFaults.push(recorded);
                log.writeEvent({
                    eventType: 'participant-selected-proof-retry',
                    details: recorded,
                });
            }
        }),
    );
    await expectStatus(0, 'cast-ballot', 'refused', {
        scores: ballotScores(0),
    });
    // A successful POST is insufficient: activation must read back
    // the complete named certificate before retiring preparation.
    // These views affect GET only; the relay still accepts each write.
    const setupPublicationFaults: Record<string, unknown>[] = [];
    const activationHead = await retainedHead(setupReplay);
    assert.equal(activationHead.generation, 4);
    const activationRecords = {
        contribution: await storedRecords(setupReplay, 'contribution'),
        checkpoint: await storedRecords(setupReplay, 'checkpoint'),
    };
    assert.ok(activationRecords.contribution > 0);
    assert.equal(
        await stat(path.join(publicDirectory, 'setup-certificate.bin')).catch(
            () => undefined,
        ),
        undefined,
    );
    for (const changed of [undefined, Buffer.from([0])]) {
        const hidden = 'setup-certificate.bin';
        views[setupReplay].set(hidden, changed);
        const before = relay.publicationAttempts[setupReplay];
        try {
            const pending = await request(setupReplay, 'verify-setup');
            assert.deepEqual(pending, {
                status: 'pending',
                cause: 'public input',
                detail:
                    changed === undefined
                        ? 'A public record is unavailable.'
                        : 'Published manifest readback differs.',
            });
            assert.ok(
                relay.publicationAttempts[setupReplay] > before,
                'Activation did not attempt the acknowledged setup publication.',
            );
            assert.ok(
                (await stat(path.join(publicDirectory, hidden))).size > 0,
                'The relay did not retain the acknowledged setup write.',
            );
            assert.deepEqual(
                await retainedHead(setupReplay),
                activationHead,
                'A setup publication without readback changed the preparation root.',
            );
            assert.deepEqual(
                {
                    contribution: await storedRecords(
                        setupReplay,
                        'contribution',
                    ),
                    checkpoint: await storedRecords(setupReplay, 'checkpoint'),
                },
                activationRecords,
                'A setup publication without readback retired own preparation.',
            );
            const fault = {
                position: setupReplay,
                hidden,
                generation: 4,
                result: pending,
                acknowledgedWriteRetained: true,
                originalPreparationRetained: true,
            };
            setupPublicationFaults.push(fault);
            log.writeEvent({
                eventType: 'participant-setup-publication-fault',
                details: fault,
            });
        } finally {
            views[setupReplay].delete(hidden);
        }
    }
    const lateSetup = mode === 'empty' ? participantCount - 1 : undefined;
    const verificationReplay = [
        ...otherMembers,
        ...[...contributors].reverse(),
    ].find((position) => honest(position) && position !== lateSetup);
    assert.ok(verificationReplay !== undefined);
    if (mode === 'preparation')
        await refuseLostSource(verificationReplay, 'verify-setup');
    await Promise.all(
        positions
            .filter((position) => position !== lateSetup)
            .map(async (position) => {
                if (position === verificationReplay) {
                    await interrupt(position, 'verify-setup', {}, 12);
                    const status = await run(position, 'status');
                    assert.equal(status.generation, 12);
                    assert.equal(status.ballotState, 'open');
                    return;
                }
                const verified = await run(position, 'verify-setup');
                assert.equal(verified.generation, 12);
                assert.equal(verified.ballotState, 'open');
            }),
    );
    for (const position of positions.filter(
        (candidate) => candidate !== lateSetup,
    ))
        for (const operation of [
            'confirm',
            'contribute',
            'select-setup',
            'endorse-setup',
            'verify-setup',
        ] as const)
            await expectStatus(position, operation, 'refused');
    if (mode === 'preparation') {
        const sourceRestarts: Record<string, unknown>[] = [];
        const publishedShape = async () =>
            Promise.all(
                (await publicRecordNames(publicDirectory))
                    .sort()
                    .map(async (name) => ({
                        name,
                        bytes: (await stat(path.join(publicDirectory, name)))
                            .size,
                    })),
            );
        const publicBefore = await publishedShape();
        for (const position of positions) {
            const before = await retainedHead(position);
            assert.equal(before.generation, 12);
            await inspectSourceCustody(position, 'verified setup');
            await endBrowser(position);
            const restored = await run(position, 'status');
            assert.equal(restored.generation, 12);
            assert.equal(
                restored.registrationBodyDigest,
                registrationBodyDigests[position],
            );
            assert.equal(restored.ballotState, 'open');
            // With no closeTime and no published intent, close only
            // restores the credential-authenticated setup and scans
            // the empty ballot inventory; it creates no close intent.
            const attempts: number = relay.publicationAttempts[position];
            const ready = await run(position, 'close');
            assert.equal(ready.generation, 12);
            assert.equal(ready.ballotState, 'open');
            assert.equal(relay.publicationAttempts[position], attempts);
            assert.equal(await storedRecords(position, 'contribution'), 0);
            assert.equal(await storedRecords(position, 'checkpoint'), 0);
            assert.deepEqual(
                await retainedHead(position),
                before,
                'Prepared recovery replaced the original root.',
            );
            await inspectSourceCustody(position, 'cold prepared recovery');
            const details = {
                position,
                generation: 12,
                originalBodyDigest: registrationBodyDigests[position],
                restoredSetup: true,
                privatePreparationRetired: true,
            };
            sourceRestarts.push(details);
            log.writeEvent({
                eventType: 'participant-prepared-source-recovery',
                details,
            });
        }
        // The relay compares every repeated span byte-for-byte;
        // unchanged names and lengths also exclude appended records.
        assert.deepEqual(
            await publishedShape(),
            publicBefore,
            'Prepared recovery extended or replaced public setup records.',
        );
        assert.equal(paddingInterruptions.length, 2);
        const last = paddingInterruptions[1];
        const proofPath = path.join(
            publicDirectory,
            (await offerDirectory(last.position)) + 'proof.bin',
        );
        const header = await readFile(
            path.join(
                publicDirectory,
                (await offerDirectory(last.position)) + 'body-header.bin',
            ),
        );
        assert.equal(header.length, bounds.contribution.bodyHeaderBytes);
        assert.equal(header.subarray(0, 4).toString('ascii'), 'SCB2');
        assert.equal(
            header.readBigUInt64LE(4),
            BigInt(last.observation.halt.proofBytes),
        );
        assert.equal(
            (await stat(proofPath)).size,
            last.observation.halt.proofBytes,
            'Publication extended the logical proof with private padding.',
        );
        const published = await open(proofPath, 'r');
        const slotBytes = Buffer.alloc(chunkBytes);
        try {
            for (const slot of last.observation.slots) {
                slotBytes.fill(0);
                const used = Math.max(
                    0,
                    Math.min(
                        slot.length,
                        last.observation.halt.proofBytes - slot.offset,
                    ),
                );
                let read = 0;
                while (read < used) {
                    const result = await published.read(
                        slotBytes,
                        read,
                        used - read,
                        slot.offset + read,
                    );
                    assert.ok(result.bytesRead > 0);
                    read += result.bytesRead;
                }
                assert.equal(
                    createHash('sha512')
                        .update(slotBytes.subarray(0, slot.length))
                        .digest('hex'),
                    slot.sha512,
                    'Published proof differs from the private replay diagnostic.',
                );
            }
        } finally {
            slotBytes.fill(0);
            await published.close();
        }
        const [first, final] = paddingInterruptions.map(
            (entry) => entry.observation.halt,
        );
        await writeFile(
            path.join(log.runDirectoryPath, 'result.json'),
            JSON.stringify(
                {
                    participantCount,
                    optionCount,
                    mode,
                    scalar,
                    poll: organizer.poll,
                    registrationBodyDigests,
                    runtimeIdentity: runtime.identity.runtime,
                    peakProcessTreeBytes: peaks,
                    transfers,
                    sampledResources,
                    interruptions,
                    paddingInterruptions,
                    paddingRefusals,
                    sourceCustody,
                    sourceRefusals,
                    stateLosses,
                    setupPublicationFaults,
                    selectionReadbackFaults,
                    selectedProofFaults,
                    sourceRestarts,
                    coincidentPaddingCuts:
                        first.slotOffset === final.slotOffset,
                    logicalProofBytes: last.observation.halt.proofBytes,
                    scope: 'Clear fixed-roster preparation only: local confirmation, real signed-offer generation and original-intent restart, organizer selection, quorum endorsements and every original member setup verifier. Missing or damaged required source capsules stop copied original namespaces; verified setup retires its source capsule and wrapping key, and cold recovery restores the original credential and setup without them. Before certification, contributors retransmit identical signed offers; certification retires private preparation while the public records remain retrievable. Harness-only pauses and private plaintext proof digests measure padding replay; their work is included in interrupted operations. This instrumented development run does not exercise departure tolerance, ballots or outcome and establishes no exact-build qualification or phone support.',
                },
                null,
                2,
            ) + '\n',
            { flag: 'wx' },
        );
        return;
    }
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
        assert.equal(envelope.readBigUInt64LE(142), BigInt(body.size));
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
            ).readBigUInt64LE(134),
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
    assert.ok(responseEvents.length >= bounds.close.quorum - 1);
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
    for (let index = 0; index < closeBounds.quorum; index++)
        named.push(
            proposal.readUInt16LE(
                4 +
                    closeBounds.proposalBodyBytes -
                    (closeBounds.quorum - index) * 66,
            ),
        );
    assert.deepEqual(named, [0, ...responders].slice(0, closeBounds.quorum));
    // The profile's inventory certificate threshold is also the close
    // quorum. The last corrupt positions beyond it among the
    // participants that did not depart sign no target vote; they
    // release later from their completed close.
    const nonVoters = positions.slice(
        1 +
            maximumCorruptParticipantCount -
            (participantCount - departed.size - closeBounds.quorum),
        1 + maximumCorruptParticipantCount,
    );
    const voters = positions.filter(
        (position) => !nonVoters.includes(position) && !departed.has(position),
    );
    assert.equal(voters.length, closeBounds.quorum);
    // Every voter verifies the barrier, classifies each usable
    // ballot, evaluates the target and signs its vote. Every on-time
    // ballot but the equivocator's and the omitted one is usable,
    // every usable ballot but the invalid author's is valid, the
    // omitted voter's ballot is reported omitted, a late one late,
    // and a participant without a ballot has none cast.
    // The equivocator and the invalid author are non-voters.
    assert.ok(
        [equivocator, invalidAuthor].every(
            (position) =>
                position === undefined || nonVoters.includes(position),
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
    // A voter releases after its signed target and a non-voter after
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
            assert.equal(details.encrypted, false);
            assert.equal(details.predecessor, undefined);
            assert.equal(details.resumedFrom, undefined);
            // A non-voter reads its status from the certified target.
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
            assert.equal(details.encrypted, true);
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
                    assert.equal(details.encrypted, true);
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
        assert.equal(delivered.encrypted, undefined);
        // A release after the completed close spent the target
        // purpose, and its lock retains the own ballot's status.
        for (const position of nonVoters) {
            await expectStatus(position, 'sign-target', 'refused');
            assert.equal(
                (await run(position, 'status')).ballotInclusion,
                ballotInclusion(position),
            );
        }
        // A signed release is only delivered again.
        const rereleased = await run(combiningPosition, 'release');
        assert.equal(rereleased.generation, 29);
        assert.equal(rereleased.encrypted, undefined);
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
    // The last remaining participant combines the published shares
    // into the requested prefix of the ranking of the on-time ballots'
    // score totals, ties to the lower option, or finds that the
    // certified target carries no result. The equivocator's ballots
    // and the omitted ballot are not counted. The departed organizer's
    // share is absent, so the first share it tries is unavailable, and
    // the lowest remaining shares include a non-voter's when one
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
        assert.ok(page.ids.length > 0);
        const source = await fetch(base + '/candidate/' + page.ids[0]);
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
        const readback = await fetch(base + '/candidate/' + receipt.id);
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
                .ids[0],
            receipt.id,
        );
        log.writeEvent({
            eventType: 'participant-replayed-candidate',
            details: { sourceKey, targetKey, candidate: receipt.id },
        });
        return receipt.id;
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
        encrypted: unknown;
        identifiers: unknown;
    }[] = [];
    const probeForeignPoll = async (position: number) => {
        if (foreign === undefined) return;
        assert.notEqual(foreign.poll, organizer.poll);
        for (const { family, pattern, details } of foreignFamilies) {
            // Only an encrypted target's result reads release shares,
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
                const { encrypted, identifiers } = await probeUnread(
                    position,
                    view,
                );
                unreadOutcomes.push({ family, encrypted, identifiers });
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
                for (const id of voteReplays)
                    assert.ok(
                        candidateReads[position].has(id),
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
                            (id) =>
                                'No valid complete candidate is available: registration/' +
                                id,
                        ),
                );
            }
            if (position === shareProbe && !noResult) {
                await probe(
                    position,
                    shareForgeries,
                    'The release shares are incomplete.',
                );
                for (const id of shareReplays)
                    assert.ok(
                        candidateReads[position].has(id),
                        'The verifier did not encounter the replayed release candidate.',
                    );
            }
            if (position === voteProbe) await probeForeignPoll(position);
        }),
    ]);
    assert.equal(result.encrypted, !noResult);
    assert.deepEqual(result.identifiers, noResult ? [] : expectedResult);
    for (const { family, encrypted, identifiers } of unreadOutcomes) {
        assert.equal(encrypted, result.encrypted, family);
        assert.deepEqual(identifiers, result.identifiers, family);
    }
    // None of the forged views stopped its participant or withdrew
    // its ballot: with the relay's own records it combines the same
    // outcome.
    const recovered = await run(voteProbe, 'compute-result');
    assert.equal(recovered.encrypted, result.encrypted);
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
    assert.equal(recomputed.encrypted, result.encrypted);
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
    // with the standalone verifier from the poll's identity and the
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
        assert.equal(verified.details.encrypted, result.encrypted);
        assert.deepEqual(verified.details.identifiers, result.identifiers);
    }
    const scope = [
        mode === 'empty'
            ? "Browser registration, roster agreement, setup contribution and setup verification with no ballot cast, a participant whose setup is retained only after the organizer's close intent and so can no longer vote, close responses that list nothing under the organizer's proposal, a participant refused a ballot after its intent lock, target evaluation and votes, and a certified no-result target for which the participants remaining after the organizer departs with its private state release nothing, in the maintained participant runtime in external Chrome."
            : noResult
              ? "Browser registration, roster agreement, setup contribution, setup verification, signed ballots, close responses with the organizer's proposal at a close time that leaves one valid on-time ballot fewer than the minimum turnout, beside a corrupt participant's authentic invalid ballot when the profile tolerates one, target evaluation and votes, and a certified no-result target for which the participants remaining after the organizer departs with its private state release nothing, in the maintained participant runtime in external Chrome."
              : "Browser registration, roster agreement, setup contribution, setup verification, signed ballots, one of them the all-minimum ballot, close responses with the organizer's proposal, and target evaluation and votes, release shares after the organizer departs with its private state, one of them generated again from its retained seed after its browser closed while generating it, and any beyond the certificate quorum released without a target vote, and the combined shorter result in the maintained participant runtime in external Chrome. A corrupt participant that copies its private state signs two more ballots, one of them late, and the relay's views make its slot conflicting, so none of its ballots counts.",
        ...(departing === undefined || omittedVoter === undefined
            ? []
            : [
                  "An honest participant departs with its private state after preparation and before the close, casting nothing. The relay hides another honest voter's on-time ballot from every other participant and serves its close response only after the organizer's proposal, so the proposal omits that ballot and its voter's target reports the omission.",
              ]),
        'A registrant that the organizer leaves out of the roster stays pending when shown it.',
        'The organizer crashes with its roster proposal intent and the last honest participant right after it retains the accepted roster, and an honest participant crashes while it verifies the setup and right after it retains the verified setup; each next visit continues from its retained state, verifying the setup again from the public records after the first of those crashes.',
        'Every participant locally confirms the fixed roster. Selected eligible contributors publish signed clear offers; the organizer proposes the selection and members endorse it before setup activation. The cohort interrupts original contribution and continuation work, the offer-signing intent, the organizer selection intent and one endorsement intent; each next visit preserves its original seed, checkpoint, signing intent and independently retained preparation state.',
        `Honest browsers crash right after their participants durably enter each ${mode === 'empty' ? 'close and target' : noResult ? 'ballot, close and target' : 'ballot, close, target and release'} generation, and each next visit continues from the retained state.`,
        mode === 'empty'
            ? "Copies of honest participants' state that lose their last data record before their close response or target vote stop for good."
            : "Copies of honest participants' state stop for good once they lose their last ballot record with the ballot body retained, or, before their close response or target vote, their last close record or, holding none, their last data record.",
        `Relay views that ${noResult ? 'relabel or replay votes' : 'relabel, replay or alter votes and shares'} or swap two registrations under each other's names leave their participants pending until the relay's own records let them finish, and altered retained state stops a participant for good.`,
        ...(mode === 'empty'
            ? []
            : [
                  "Relay views that alter or withhold the body of a participant's own counted ballot, replace its submission with another counted author's authentic one or alter its signature leave that participant's result visit pending, and with the relay's own records it reaches the same outcome from the certified target that counts the ballot.",
              ]),
        ...(foreign === undefined
            ? []
            : [
                  `Relay views that serve another poll's ${prose(foreignProbes.filter(({ detail }) => detail !== undefined).map(({ family }) => family))} under this poll's names leave a participant pending, and its ${prose(unreadOutcomes.map(({ family }) => family))}, which a result visit that restores the verified setup and the evaluated target does not read, leave that visit the same outcome.`,
              ]),
        "Once its altered retained state stops a participant, that participant and the registrant left out of the roster each verify the same outcome with the standalone verifier from the poll's identity and the relay's public records alone.",
    ].join(' ');
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
                nonVoters,
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
                scope,
            },
            null,
            2,
        ) + '\n',
        { flag: 'wx' },
    );
};
