import { afterEach, describe, expect, it } from 'vitest';

import { ballotRecordAssociatedData } from '#packages/sdk/src/participant/worker/ballot-state.js';
import type { BallotSession } from '#packages/sdk/src/participant/worker/ballot.js';
import {
    readParticipantLimits,
    readParticipantProfile,
} from '#packages/sdk/src/participant/worker/bounds.js';
import {
    closeEventKind,
    closeRecordAssociatedData,
    collectingCloseState,
} from '#packages/sdk/src/participant/worker/close-state.js';
import { heldBallotBody } from '#packages/sdk/src/participant/worker/close.js';
import type { CloseSession } from '#packages/sdk/src/participant/worker/close.js';
import {
    custodyIdentity,
    custodyPurpose,
} from '#packages/sdk/src/participant/worker/identity.js';
import { instantiateParticipantKernel } from '#packages/sdk/src/participant/worker/kernel.js';
import { noParallelHelpers } from '#packages/sdk/src/participant/worker/parallel.js';
import { sealRecord } from '#packages/sdk/src/participant/worker/records.js';
import {
    openParticipantDatabase,
    participantDatabaseName,
} from '#packages/sdk/src/participant/worker/storage.js';

const opened: IDBDatabase[] = [];
const names: string[] = [];
const module = await WebAssembly.compile(
    await (
        await fetch(new URL('../../../dist/participant.wasm', import.meta.url))
    ).arrayBuffer(),
);
const { kernel: boundsKernel } = await instantiateParticipantKernel(
    module,
    noParallelHelpers,
);
const profile = readParticipantProfile(
    boundsKernel,
    readParticipantLimits(boundsKernel),
    3,
    2,
);
if (profile === undefined) throw new Error('The fixture profile was refused.');
const requestResult = <Value>(request: IDBRequest<Value>) =>
    new Promise<Value>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
            reject(request.error ?? new Error('Fixture read failed.'));
    });
const write = (
    database: IDBDatabase,
    change: (store: IDBObjectStore) => void,
    storeName: 'close' | 'ballot' = 'close',
) =>
    new Promise<void>((resolve, reject) => {
        const transaction = database.transaction(storeName, 'readwrite');
        transaction.oncomplete = () => resolve();
        transaction.onabort = () =>
            reject(transaction.error ?? new Error('Fixture write failed.'));
        change(transaction.objectStore(storeName));
    });

// This isolates ciphertext custody and selection, using real IndexedDB,
// AES-GCM and the module's envelope identity. The synthetic envelope and body
// supply custody bytes; protocol proof acceptance remains the real cohort's
// boundary.
const fixture = async (author = 1) => {
    const namespace = 'held-' + crypto.randomUUID();
    names.push(namespace);
    const database = await openParticipantDatabase(namespace);
    opened.push(database);
    const body = Uint8Array.from(
        { length: profile.ballot.minimumBodyBytes + 37 },
        (_unused, index) => (17 * index + 3) % 251,
    );
    const envelope = new Uint8Array(profile.ballot.envelopeBytes);
    const view = new DataView(envelope.buffer);
    view.setUint16(132, author, true);
    view.setBigUint64(142, BigInt(body.length), true);
    const submission = new Uint8Array(profile.close.submissionBytes);
    submission.set(envelope);
    const { kernel } = await instantiateParticipantKernel(
        module,
        noParallelHelpers,
    );
    expect(kernel.worker_reserve(0, 0)).toBe(0);
    const identity = custodyIdentity(kernel, custodyPurpose.envelope, envelope);
    const records = {
        poll: new Uint8Array(64).fill(2),
        runtime: new Uint8Array(64).fill(3),
        inventory: new Uint8Array(64).fill(4),
        position: 0,
    };
    const event = {
        kind: closeEventKind.held,
        serial: 0,
        length: body.length,
        keys: [] as Uint8Array[],
    };
    const plaintexts = [submission];
    for (
        let offset = 0;
        offset < body.length;
        offset += profile.ballot.recordBytes
    )
        plaintexts.push(
            body.subarray(offset, offset + profile.ballot.recordBytes),
        );
    const ciphertexts: Uint8Array[] = [];
    for (const [index, bytes] of plaintexts.entries()) {
        const sealed = await sealRecord(
            closeRecordAssociatedData(records, event, index, bytes.length),
            bytes,
        );
        event.keys.push(sealed.key);
        ciphertexts.push(sealed.ciphertext);
    }
    await write(database, (store) => {
        for (const [index, bytes] of ciphertexts.entries())
            store.add(new Blob([new Uint8Array(bytes)]), [0, index]);
    });
    const session = {
        participant: { context: { database, profile, kernel, position: 0 } },
        records,
        ballot: undefined,
        state: { ...collectingCloseState(), events: [event] },
    } as unknown as CloseSession;
    return {
        database,
        body,
        envelope,
        identity,
        records,
        session,
        ciphertexts,
    };
};

afterEach(async () => {
    for (const database of opened.splice(0)) database.close();
    for (const name of names.splice(0))
        await requestResult(
            indexedDB.deleteDatabase(participantDatabaseName(name)),
        );
});

describe('held ballot custody reads', () => {
    it('uses the own retained ballot and refuses loss of its required record', async () => {
        const fixed = await fixture(0);
        const keys: Uint8Array[] = [];
        const ciphertexts: Uint8Array[] = [];
        for (
            let offset = 0;
            offset < fixed.body.length;
            offset += profile.ballot.recordBytes
        ) {
            const bytes = fixed.body.subarray(
                offset,
                offset + profile.ballot.recordBytes,
            );
            const sealed = await sealRecord(
                ballotRecordAssociatedData(
                    fixed.records,
                    keys.length,
                    bytes.length,
                ),
                bytes,
            );
            keys.push(sealed.key);
            ciphertexts.push(sealed.ciphertext);
        }
        await write(
            fixed.database,
            (store) => {
                for (const [index, bytes] of ciphertexts.entries())
                    store.add(new Blob([new Uint8Array(bytes)]), index);
            },
            'ballot',
        );
        const ballot = {
            participant: fixed.session.participant,
            records: fixed.records,
            state: {
                envelope: fixed.envelope,
                bodyKeys: keys,
                bodyLength: fixed.body.length,
            },
        } as unknown as BallotSession;
        const session = {
            ...fixed.session,
            ballot,
            state: collectingCloseState(),
        };
        const reader = await heldBallotBody(session, 0, fixed.identity);
        const output = new Uint8Array(fixed.body.length);
        let offset = 0;
        expect(
            await reader!((bytes) => {
                output.set(bytes, offset);
                offset += bytes.length;
            }),
        ).toBe(fixed.body.length);
        expect(
            output.findIndex((byte, index) => byte !== fixed.body[index]),
        ).toBe(-1);
        await write(fixed.database, (store) => store.delete(0), 'ballot');
        await expect(reader!(() => undefined)).rejects.toThrow('missing');
    });

    it('reads the exact body repeatedly, preserves its stored bytes and clears temporary plaintext', async () => {
        const fixed = await fixture();
        for (let attempt = 0; attempt < 2; attempt++) {
            const reader = await heldBallotBody(
                fixed.session,
                1,
                fixed.identity,
            );
            expect(reader).toBeDefined();
            const output = new Uint8Array(fixed.body.length);
            const views: Uint8Array[] = [];
            let offset = 0;
            expect(
                await reader!((bytes) => {
                    output.set(bytes, offset);
                    offset += bytes.length;
                    views.push(bytes);
                }),
            ).toBe(fixed.body.length);
            expect(output.length).toBe(fixed.body.length);
            expect(
                output.findIndex((byte, index) => byte !== fixed.body[index]),
            ).toBe(-1);
            expect(
                views.every((bytes) => bytes.every((byte) => byte === 0)),
            ).toBe(true);
        }
        expect(
            await heldBallotBody(fixed.session, 2, fixed.identity),
        ).toBeUndefined();
        expect(
            await heldBallotBody(fixed.session, 1, new Uint8Array(64)),
        ).toBeUndefined();
    });

    it('refuses a missing or damaged required body instead of supplying a replacement', async () => {
        const fixed = await fixture();
        const last = fixed.ciphertexts.length - 1;
        const reader = await heldBallotBody(fixed.session, 1, fixed.identity);
        await write(fixed.database, (store) => store.delete([0, last]));
        await expect(reader!(() => undefined)).rejects.toThrow('missing');
        const changed = fixed.ciphertexts[last].slice();
        changed[0] ^= 1;
        await write(fixed.database, (store) =>
            store.put(new Blob([changed]), [0, last]),
        );
        await expect(reader!(() => undefined)).rejects.toThrow();
    });

    it('refuses a substituted record, another inventory and a missing held envelope', async () => {
        const fixed = await fixture();
        const reader = await heldBallotBody(fixed.session, 1, fixed.identity);
        await write(fixed.database, (store) =>
            store.put(new Blob([new Uint8Array(fixed.ciphertexts[2])]), [0, 1]),
        );
        await expect(reader!(() => undefined)).rejects.toThrow();
        fixed.records.inventory[0] ^= 1;
        await expect(
            heldBallotBody(fixed.session, 1, fixed.identity),
        ).rejects.toThrow();
        fixed.records.inventory[0] ^= 1;
        await write(fixed.database, (store) => store.delete([0, 0]));
        await expect(
            heldBallotBody(fixed.session, 1, fixed.identity),
        ).rejects.toThrow('missing');
    });

    it('propagates consumer refusal and clears the delivered plaintext', async () => {
        const fixed = await fixture();
        const reader = await heldBallotBody(fixed.session, 1, fixed.identity);
        let delivered: Uint8Array | undefined;
        await expect(
            reader!((bytes) => {
                delivered = bytes;
                throw new Error('Owning verifier refused');
            }),
        ).rejects.toThrow('Owning verifier refused');
        expect(delivered?.every((byte) => byte === 0)).toBe(true);
    });
});
