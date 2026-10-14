import assert from 'node:assert/strict';
import { cp, rm } from 'node:fs/promises';
import path from 'node:path';

import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';
import {
    type Relay,
    participantDatabase,
    participantNamespace,
} from '#tools/ci/participant-browser-relay.js';
import type { ParticipantRequests } from '#tools/ci/participant-browser-requests.js';
import {
    type CohortState,
    type InParticipantBrowser,
    pressurePages,
    type ParticipantOperation,
    databaseScript,
} from '#tools/ci/participant-cohort-state.js';
import type { SourceCustodyObservation } from '#tools/ci/participant-preparation-storage.js';
import { assembleParticipantRuntime } from '#tools/ci/participant-runtime-assembly.js';

export const createParticipantStateFaults = ({
    inBrowser,
    browsers,
    participantBrowser,
    pressured,
    request,
    memoryPressures,
    log,
    browserProfilePath,
    copyProfile,
    copies,
    copyBrowser,
    preparationStorageBundle,
    runtime,
    honest,
    relay,
    organizer,
    hexadecimal,
    definition,
    definitionSignature,
}: Readonly<{
    inBrowser: InParticipantBrowser;
    browsers: CohortState['browsers'];
    participantBrowser: (position: number) => string;
    pressured: CohortState['pressured'];
    request: ParticipantRequests['request'];
    memoryPressures: CohortState['memoryPressures'];
    log: ActiveLocalRunLog;
    browserProfilePath: (position: number) => string;
    copyProfile: (copy: string) => string;
    copies: CohortState['copies'];
    copyBrowser: (copy: string) => string;
    preparationStorageBundle: string | undefined;
    runtime: Awaited<ReturnType<typeof assembleParticipantRuntime>>['runtime'];
    honest: (position: number) => boolean;
    relay: Relay;
    organizer: Readonly<{ poll: string }>;
    hexadecimal: (bytes: Uint8Array) => string;
    definition: Buffer;
    definitionSignature: Buffer;
}>) => {
    // Reads the generation of a participant's committed head from its
    // own page, reading nothing else.
    const headGeneration = async (position: number, copy?: string) =>
        Number(
            await inBrowser(position, copy, (chrome) =>
                chrome.evaluate(
                    databaseScript(
                        participantDatabase,
                        `return (await result(database.transaction('head').objectStore('head').get(0)))?.generation ?? 0;`,
                    ),
                ),
            ),
        );
    const retainedHead = async (position: number, copy?: string) =>
        inBrowser(position, copy, (chrome) =>
            chrome.evaluate(
                databaseScript(
                    participantDatabase,
                    `return await result(database.transaction('head').objectStore('head').get(0));`,
                ),
            ),
        ) as Promise<{
            generation: number;
            hash: string;
            runtime: string;
        }>;
    // Counts a participant's records in one store from its own page,
    // reading none of them.
    const storedRecords = async (position: number, store: string) =>
        Number(
            await inBrowser(position, undefined, (chrome) =>
                chrome.evaluate(
                    databaseScript(
                        participantDatabase,
                        `return await result(database.transaction(${JSON.stringify(store)}).objectStore(${JSON.stringify(store)}).count());`,
                    ),
                ),
            ),
        );
    // Ends a participant's browser as a crash would. Its committed
    // state is what the next launch finds, while Chrome's own
    // shutdown can outlast its deadline when other browsers write.
    const endBrowser = async (position: number) => {
        await browsers.crash(participantBrowser(position));
    };
    // Runs a participant's operation in a browser that caps each
    // WebAssembly memory at the pressure pages. Exhausting that bound
    // leaves the participant pending, not stopped, whatever its
    // operation retained; the capped browser then ends.
    const pressure = async (
        position: number,
        operation: ParticipantOperation,
    ) => {
        await endBrowser(position);
        pressured.add(position);
        try {
            const before = await headGeneration(position);
            const result = await request(position, operation);
            assert.ok(
                result.status === 'pending' &&
                    result.cause === 'resource' &&
                    result.detail.includes('exhausted its memory bound'),
                `${operation} at position ${String(position)} under memory pressure: ${JSON.stringify(result)}`,
            );
            const details = {
                position,
                operation,
                pages: pressurePages,
                before,
                generation: await headGeneration(position),
                detail: result.detail,
            };
            memoryPressures.push(details);
            log.writeEvent({
                eventType: 'participant-memory-pressure',
                details,
            });
        } finally {
            await endBrowser(position);
            pressured.delete(position);
        }
    };
    // Copies a participant's private state into its own Chrome
    // profile at the participant's origin, whose browser opens when
    // the copy acts. The participant's browser ends first, so the
    // copy holds exactly the committed state its next launch would
    // find; crash reporting state is not participant state, and its
    // handler can outlive the browser.
    const copyState = async (position: number, copy: string) => {
        await endBrowser(position);
        await cp(browserProfilePath(position), copyProfile(copy), {
            recursive: true,
            errorOnExist: true,
            force: false,
            filter: (source) =>
                path.relative(browserProfilePath(position), source) !==
                'Crashpad',
        });
        copies.set(copy, position);
    };
    const removeCopy = async (copy: string) => {
        await browsers.crash(copyBrowser(copy));
        copies.delete(copy);
        await rm(copyProfile(copy), {
            recursive: true,
            maxRetries: 10,
            retryDelay: 500,
        });
    };
    const sourceCustody: (SourceCustodyObservation & {
        position: number;
        stage: string;
    })[] = [];
    const sourceRefusals: Record<string, unknown>[] = [];
    const inspectSourceCustody = async (
        position: number,
        stage: string,
        copy?: string,
        mutation?: 'missing' | 'damaged',
    ) => {
        assert.ok(preparationStorageBundle);
        const observed = (await inBrowser(position, copy, (chrome) =>
            chrome.evaluate(
                preparationStorageBundle +
                    '\nparticipantPreparationFixture.inspectParticipantSourceCustody(' +
                    JSON.stringify({
                        namespace: participantNamespace,
                        runtimeIdentity: runtime.identity.runtime,
                        moduleDigest: runtime.identity.module,
                        mutation,
                    }) +
                    ');',
            ),
        )) as SourceCustodyObservation;
        const required = observed.generation < 12;
        assert.equal(
            observed.dataKeyBytes,
            required ? 3 * 32 : 2 * 32,
            'The root retained another data-key inventory.',
        );
        assert.equal(
            observed.sourceReferences,
            required ? 1 : 0,
            'The root retained another source reference inventory.',
        );
        assert.equal(
            observed.sourceRecords,
            required ? 1 : 0,
            'The data store retained another source capsule inventory.',
        );
        const details = { position, stage, ...observed };
        if (copy === undefined) sourceCustody.push(details);
        log.writeEvent({
            eventType: 'participant-source-custody',
            details: { ...details, copy, mutation },
        });
        return observed;
    };
    const refuseLostSource = async (
        position: number,
        operation: ParticipantOperation,
    ) => {
        assert.ok(honest(position));
        assert.ok(relay);
        for (const mutation of ['missing', 'damaged'] as const) {
            const copy = `source-${mutation}-${position}-${operation}`;
            await copyState(position, copy);
            try {
                const before = await retainedHead(position, copy);
                const observed = await inspectSourceCustody(
                    position,
                    'before fault',
                    copy,
                    mutation,
                );
                assert.ok(observed.generation < 12);
                const publications: number =
                    relay.publicationAttempts[position];
                const refused = await request(position, operation, {}, copy);
                assert.deepEqual(refused, {
                    status: 'stopped',
                    stopPersistence: 'confirmed',
                    detail:
                        mutation === 'missing'
                            ? 'Participant data inventory changed.'
                            : 'A participant data record changed.',
                });
                assert.deepEqual(
                    await retainedHead(position, copy),
                    before,
                    'A damaged source replaced the original root authority.',
                );
                await browsers.crash(copyBrowser(copy));
                const stopped = await request(position, 'status', {}, copy);
                assert.deepEqual(stopped, {
                    status: 'stopped',
                    stopPersistence: 'confirmed',
                    detail: 'Missing or inconsistent participant authority.',
                });
                const replacement = await request(
                    position,
                    'create',
                    {
                        role: 'joiner',
                        poll: organizer.poll,
                        definition: hexadecimal(definition),
                        definitionSignature: hexadecimal(definitionSignature),
                        username: 'Replacement refused',
                    },
                    copy,
                );
                assert.deepEqual(replacement, {
                    status: 'refused',
                    reason: 'participant exists',
                });
                assert.deepEqual(await retainedHead(position, copy), before);
                assert.equal(
                    relay.publicationAttempts[position],
                    publications,
                    'A source fault caused a relay publication attempt.',
                );
                const details = {
                    position,
                    generation: observed.generation,
                    operation,
                    mutation,
                    result: refused,
                    coldResult: stopped,
                    replacement,
                    publicationAttempts: 0,
                };
                sourceRefusals.push(details);
                log.writeEvent({
                    eventType: 'participant-source-refusal',
                    details,
                });
            } finally {
                await removeCopy(copy);
            }
        }
    };
    // Loses the last record of one store in a copy of an honest
    // participant's state and runs the operation there: the copy
    // stops with its stop persisted and stays stopped, and the copy
    // is deleted. The participant itself continues unaffected.
    const stateLosses: {
        position: number;
        store: string;
        record: unknown;
        operation: ParticipantOperation;
        generation: number;
        detail: string;
    }[] = [];
    const loseState = async (
        position: number,
        store: string,
        operation: ParticipantOperation,
        noPublications = false,
    ) => {
        assert.ok(honest(position), 'Only honest state is lost.');
        const copy = `lost-${store}-${String(position)}`;
        await copyState(position, copy);
        try {
            const generation = await headGeneration(position, copy);
            const record: unknown = await inBrowser(position, copy, (chrome) =>
                chrome.evaluate(
                    databaseScript(
                        participantDatabase,
                        `const deleting = database.transaction(${JSON.stringify(store)}, 'readwrite');
const deleted = completion(deleting);
const cursor = await result(deleting.objectStore(${JSON.stringify(store)}).openCursor(null, 'prev'));
if (cursor === null) throw new Error('No record to lose.');
const key = cursor.key;
cursor.delete();
await deleted;
return key;`,
                    ),
                ),
            );
            const publicationAttempts = relay.publicationAttempts[position];
            const result = await request(position, operation, {}, copy);
            assert.ok(
                result.status === 'stopped' &&
                    result.stopPersistence === 'confirmed',
                `${operation} after losing a ${store} record at position ${String(position)}: ${JSON.stringify(result)}`,
            );
            assert.deepEqual(await request(position, 'status', {}, copy), {
                status: 'stopped',
                detail: 'Missing or inconsistent participant authority.',
                stopPersistence: 'confirmed',
            });
            if (noPublications)
                assert.equal(
                    relay.publicationAttempts[position],
                    publicationAttempts,
                    'Missing required preparation state caused a relay publication.',
                );
            const loss = {
                position,
                store,
                record,
                operation,
                generation,
                detail: result.detail,
                ...(noPublications ? { publicationAttempts: 0 } : {}),
            };
            stateLosses.push(loss);
            log.writeEvent({
                eventType: 'participant-state-loss',
                details: loss,
            });
        } finally {
            await removeCopy(copy);
        }
    };
    return {
        headGeneration,
        endBrowser,
        storedRecords,
        retainedHead,
        pressure,
        copyState,
        removeCopy,
        sourceCustody,
        sourceRefusals,
        inspectSourceCustody,
        refuseLostSource,
        stateLosses,
        loseState,
    };
};
export type ParticipantStateFaults = ReturnType<
    typeof createParticipantStateFaults
>;
