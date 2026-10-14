import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cp, mkdir, open, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { chunkBytes } from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import {
    namespacedName,
    setupCacheName,
} from '#packages/sdk/src/participant/worker/storage/database.js';
import { type ParticipantCohort } from '#tools/ci/participant-browser-cohort.js';
import {
    generatedOfferIdentity,
    publicRecordNames,
} from '#tools/ci/participant-browser-public-records.js';
import { participantNamespace } from '#tools/ci/participant-browser-relay.js';
import { databaseScript } from '#tools/ci/participant-cohort-state.js';
import type { FaultRegistration } from '#tools/ci/participant-fault-registration.js';
export const prepareFaultCohort = async (
    cohort: Pick<
        ParticipantCohort,
        | 'positions'
        | 'setupContributorCount'
        | 'eligibleContributorCount'
        | 'run'
        | 'organizer'
        | 'expectStatus'
        | 'honest'
        | 'interrupt'
        | 'mode'
        | 'inspectSourceCustody'
        | 'refuseLostSource'
        | 'bounds'
        | 'interruptStaged'
        | 'interruptPreparation'
        | 'loseState'
        | 'interruptPadding'
        | 'paddingInterruptions'
        | 'preparationStorageBundle'
        | 'copyState'
        | 'inBrowser'
        | 'runtime'
        | 'participantCount'
        | 'optionCount'
        | 'relay'
        | 'request'
        | 'log'
        | 'removeCopy'
        | 'publicDirectory'
        | 'retainedHead'
        | 'views'
        | 'interruptDelivered'
        | 'ballotScores'
        | 'storedRecords'
        | 'endBrowser'
        | 'scalar'
        | 'peaks'
        | 'transfers'
        | 'sampledResources'
        | 'interruptions'
        | 'sourceCustody'
        | 'sourceRefusals'
        | 'stateLosses'
    >,
    registered: Pick<FaultRegistration, 'registrationBodyDigests'>,
) => {
    const {
        positions,
        setupContributorCount,
        eligibleContributorCount,
        run,
        organizer,
        expectStatus,
        honest,
        interrupt,
        mode,
        inspectSourceCustody,
        refuseLostSource,
        bounds,
        interruptStaged,
        interruptPreparation,
        loseState,
        interruptPadding,
        paddingInterruptions,
        preparationStorageBundle,
        copyState,
        inBrowser,
        runtime,
        participantCount,
        optionCount,
        relay,
        request,
        log,
        removeCopy,
        publicDirectory,
        retainedHead,
        views,
        interruptDelivered,
        ballotScores,
        storedRecords,
        endBrowser,
        scalar,
        peaks,
        transfers,
        sampledResources,
        interruptions,
        sourceCustody,
        sourceRefusals,
        stateLosses,
    } = cohort;
    const { registrationBodyDigests } = registered;
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
                // The first endorsement verifies all selected offer bodies;
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
                },
                null,
                2,
            ) + '\n',
            { flag: 'wx' },
        );
        return;
    }
    return {
        lateSetup,
        setupPublicationFaults,
        selectionReadbackFaults,
        selectedProofFaults,
    };
};

export type FaultPreparation = NonNullable<
    Awaited<ReturnType<typeof prepareFaultCohort>>
>;
