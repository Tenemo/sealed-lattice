import { createHash } from 'node:crypto';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { hexadecimal } from '#packages/sdk/src/participant/worker/bytes.js';
import type { ParticipantContext } from '#packages/sdk/src/participant/worker/context.js';
import type { RestoredEnrollment } from '#packages/sdk/src/participant/worker/enrollment.js';
import { custodyPurpose } from '#packages/sdk/src/participant/worker/identity.js';
import { publishRegistrationRecords } from '#packages/sdk/src/participant/worker/registration-publication.js';
import {
    createRootKey,
    dataKind,
    encodeManifest,
    rootAssociatedData,
    sealRoot,
} from '#packages/sdk/src/participant/worker/root.js';
import type {
    AuthenticatedRoot,
    RecordReference,
} from '#packages/sdk/src/participant/worker/root.js';
import { chunkBytes } from '#packages/sdk/src/participant/worker/runtime-bounds.js';
import { participantStores } from '#packages/sdk/src/participant/worker/storage.js';
import type { ParticipantStore } from '#packages/sdk/src/participant/worker/storage.js';
import { participantRelayFixture } from '#tests/participant-relay-fixture.js';

const local = vi.hoisted(() => ({
    read: vi.fn(),
    snapshot: vi.fn(),
    identity: vi.fn(),
}));
vi.mock(
    '#packages/sdk/src/participant/worker/storage.js',
    async (original) => ({
        ...(await original<
            typeof import('#packages/sdk/src/participant/worker/storage.js')
        >()),
        readParticipantValue: local.read,
        snapshotParticipant: local.snapshot,
    }),
);
vi.mock(
    '#packages/sdk/src/participant/worker/identity.js',
    async (original) => ({
        ...(await original<
            typeof import('#packages/sdk/src/participant/worker/identity.js')
        >()),
        custodyIdentity: local.identity,
    }),
);

// These are retained-record and transport controls, not registration proof
// acceptance. Storage reads are in-memory Blob records; an independent SHA-512
// test digest stands in for the module's custody identity. Actual root AES-GCM,
// record comparisons, delivery inspections and bounded POST encoding run here.
const digest = (purpose: number, bytes: Uint8Array) =>
    new Uint8Array(
        createHash('sha512')
            .update(Uint8Array.of(purpose))
            .update(bytes)
            .digest(),
    );
const relay = { base: 'https://relay.invalid/' };
const recordKey = (kind: number, offset: number) => `${kind}/${offset}`;
type Posted = Readonly<{ name: string; offset: number; length: number }>;

beforeEach(() => {
    local.read.mockReset();
    local.snapshot.mockReset();
    local.identity.mockReset();
});
afterEach(() => vi.unstubAllGlobals());

const fixture = async (
    keyBytes = 65_536 * 21,
    isOrganizer = false,
    generation = 1,
) => {
    const records = new Map<string, Blob>();
    const references: RecordReference[] = [];
    for (const kind of Object.values(dataKind).filter(
        (value) => value <= dataKind.proposalSignature,
    )) {
        const length = kind === dataKind.publicKey ? keyBytes : 32 + kind;
        for (let offset = 0; offset < length; offset += chunkBytes) {
            const bytes = new Uint8Array(Math.min(chunkBytes, length - offset));
            for (let index = 0; index < bytes.length; index++)
                bytes[index] = (kind * 19 + offset / chunkBytes + index) % 251;
            records.set(recordKey(kind, offset), new Blob([bytes]));
            references.push({
                kind,
                offset,
                length: bytes.length,
                hash: digest(custodyPurpose.record, bytes),
            });
        }
    }
    const manifest = {
        dataKeys: new Uint8Array(96),
        poll: new Uint8Array(64),
        references,
        suffixes: {},
    };
    const plaintext = encodeManifest(manifest, generation);
    const runtime = new Uint8Array(64).fill(13);
    const key = await createRootKey();
    const sealed = await sealRoot(
        key,
        generation,
        rootAssociatedData(runtime),
        plaintext,
    );
    const head = {
        generation,
        runtime: hexadecimal(runtime),
        hash: hexadecimal(digest(custodyPurpose.root, sealed)),
    };
    const counts = Object.fromEntries(
        participantStores.map((store) => [store, 0]),
    ) as Record<ParticipantStore, number>;
    counts.key = counts.root = counts.head = 1;
    counts.data = records.size;
    const snapshot = { key, root: sealed, head, counts };
    const root: AuthenticatedRoot = { head: { ...head }, plaintext, manifest };
    const context = { runtime } as ParticipantContext;
    const enrollment = {
        registrationBodyDigest: new Uint8Array(64).fill(3),
        isOrganizer: isOrganizer,
    } as RestoredEnrollment;
    const prefix = `registration/${hexadecimal(enrollment.registrationBodyDigest)}/`;
    const names = new Map([
        [prefix + 'polynomial-01.bin', dataKind.publicKey],
        [prefix + 'registration-header.bin', dataKind.header],
        [prefix + 'signature.bin', dataKind.signature],
        ['poll-definition.bin', dataKind.pollDefinition],
        ['poll-signature.bin', dataKind.pollSignature],
        ['proposal.bin', dataKind.proposal],
        ['proposal-signature.bin', dataKind.proposalSignature],
    ]);
    const copies: Uint8Array[] = [];
    const reads: string[] = [];
    const posts: Posted[] = [];
    local.identity.mockImplementation(
        (_module: unknown, purpose: number, bytes: Uint8Array) => {
            if (purpose === custodyPurpose.record) {
                expect(
                    copies.every((copy) => copy.every((byte) => byte === 0)),
                ).toBe(true);
                copies.push(bytes);
                expect(bytes.length).toBeLessThanOrEqual(chunkBytes);
            }
            return digest(purpose, bytes);
        },
    );
    local.read.mockImplementation(
        (
            _database: unknown,
            store: string,
            [kind, offset]: [number, number],
        ) => {
            expect(store).toBe('data');
            reads.push(recordKey(kind, offset));
            return Promise.resolve(records.get(recordKey(kind, offset)));
        },
    );
    local.snapshot.mockImplementation(() =>
        Promise.resolve({
            ...snapshot,
            head: { ...snapshot.head },
            counts: { ...counts },
        }),
    );
    const transport = participantRelayFixture();
    const send = vi.fn(async (url: string, options: RequestInit = {}) => {
        if (options.method !== 'POST' || new URL(url).pathname !== '/chunks')
            return transport.fetch(url, options);
        expect(options.body).toBeInstanceOf(Blob);
        const bytes = new Uint8Array(
            await (options.body as Blob).arrayBuffer(),
        );
        const hash = digest(custodyPurpose.record, bytes);
        const reference = references.find((item) =>
            Buffer.from(item.hash).equals(Buffer.from(hash)),
        );
        expect(reference).toBeDefined();
        const { kind, offset } = reference!;
        const name = [...names].find(([_name, value]) => value === kind)![0];
        expect(bytes.length).toBe(reference?.length);
        expect(bytes.length).toBeLessThanOrEqual(chunkBytes);
        expect(digest(custodyPurpose.record, bytes)).toEqual(reference?.hash);
        // No chunk of this kind can be posted until every reference was read.
        for (const item of references.filter((entry) => entry.kind === kind))
            expect(reads).toContain(recordKey(item.kind, item.offset));
        posts.push({ name, offset, length: bytes.length });
        return transport.fetch(url, options);
    });
    vi.stubGlobal('fetch', send);
    const corrupt = async (kind: number, offset: number) => {
        const name = recordKey(kind, offset);
        const bytes = new Uint8Array(await records.get(name)!.arrayBuffer());
        bytes[0] ^= 1;
        records.set(name, new Blob([bytes]));
    };
    return {
        publish: () =>
            publishRegistrationRecords(context, relay, root, enrollment),
        records,
        references,
        snapshot,
        counts,
        copies,
        reads,
        posts,
        send,
        corrupt,
        prefix,
    };
};

describe('bounded registration publication', () => {
    it('publishes the complete recipient key in bounded records after a complete first pass', async () => {
        const state = await fixture(65_536 * 21);
        await state.publish();
        const recipientKeyChunks = state.posts.filter(({ name }) =>
            name.endsWith('/polynomial-01.bin'),
        );
        expect(recipientKeyChunks).toHaveLength(2);
        expect(
            recipientKeyChunks.reduce((total, item) => total + item.length, 0),
        ).toBe(65_536 * 21);
        expect(recipientKeyChunks.map(({ offset }) => offset)).toEqual(
            Array.from({ length: 2 }, (_unused, index) => index * chunkBytes),
        );
        for (const reference of state.references) {
            const expectedReads = reference.kind <= dataKind.signature ? 2 : 0;
            expect(
                state.reads.filter(
                    (key) =>
                        key === recordKey(reference.kind, reference.offset),
                ),
            ).toHaveLength(expectedReads);
        }
        expect(
            state.copies.every((bytes) => bytes.every((byte) => byte === 0)),
        ).toBe(true);
        // Two snapshots open the guard, then one after each complete preflight
        // and after each upload. No registration file is concatenated.
        expect(local.snapshot).toHaveBeenCalledTimes(
            2 + 3 + state.posts.length + 1,
        );
    });

    it.each([1, 3])(
        'keeps organizer poll and roster paths at generation %s',
        async (generation) => {
            const state = await fixture(17, true, generation);
            await state.publish();
            expect(state.posts.map(({ name }) => name)).toEqual([
                state.prefix + 'polynomial-01.bin',
                state.prefix + 'registration-header.bin',
                state.prefix + 'signature.bin',
                'poll-definition.bin',
                'poll-signature.bin',
                ...(generation === 3
                    ? ['proposal.bin', 'proposal-signature.bin']
                    : []),
            ]);
        },
    );

    it('refuses corruption in the final retained key record before the first key POST', async () => {
        const state = await fixture();
        await state.corrupt(dataKind.publicKey, chunkBytes);
        await expect(state.publish()).rejects.toThrow(
            'A participant data record changed.',
        );
        expect(state.posts).toEqual([]);
    });

    it('rechecks later records after preflight and never uploads a changed chunk', async () => {
        const state = await fixture();
        const send = state.send.getMockImplementation()!;
        state.send.mockImplementation(async (url, options) => {
            const response = await send(url, options);
            const last = state.posts[state.posts.length - 1];
            if (
                options?.method === 'POST' &&
                new URL(url).pathname === '/chunks' &&
                last?.name.endsWith('/polynomial-01.bin') &&
                last.offset === 0
            )
                await state.corrupt(dataKind.publicKey, chunkBytes);
            return response;
        });
        await expect(state.publish()).rejects.toThrow(
            'A participant data record changed.',
        );
        expect(
            state.posts
                .filter(({ name }) => name.endsWith('/polynomial-01.bin'))
                .map(({ offset }) => offset),
        ).toEqual([0]);
        expect(state.posts[state.posts.length - 1]?.name).toBe(
            state.prefix + 'polynomial-01.bin',
        );
    });

    it('stops after a transport failure, clears its chunk and preserves the transport error when authority remains intact', async () => {
        const state = await fixture();
        state.send.mockRejectedValueOnce(new Error('Network disconnected.'));
        await expect(state.publish()).rejects.toThrow('Network disconnected.');
        expect(state.send).toHaveBeenCalledOnce();
        expect(state.reads).toEqual([
            recordKey(0, 0),
            recordKey(0, chunkBytes),
            recordKey(0, 0),
        ]);
        expect(
            state.copies.every((bytes) => bytes.every((byte) => byte === 0)),
        ).toBe(true);
        expect(local.snapshot).toHaveBeenCalledTimes(4);
    });

    it.each(['head', 'root', 'count'] as const)(
        'gives %s loss precedence over a failed transfer and sends nothing afterward',
        async (loss) => {
            const state = await fixture();
            state.send.mockImplementationOnce(() => {
                if (loss === 'head') state.snapshot.head.generation++;
                if (loss === 'root') state.snapshot.root[0] ^= 1;
                if (loss === 'count') state.counts.data--;
                return Promise.reject(new Error('Network disconnected.'));
            });
            await expect(state.publish()).rejects.toThrow(
                'The participant authority changed during delivery.',
            );
            expect(state.send).toHaveBeenCalledOnce();
            expect(state.reads).toEqual([
                recordKey(0, 0),
                recordKey(0, chunkBytes),
                recordKey(0, 0),
            ]);
            expect(
                state.copies.every((bytes) =>
                    bytes.every((byte) => byte === 0),
                ),
            ).toBe(true);
        },
    );

    it('inspects authority after complete-kind preflight before its first upload', async () => {
        const state = await fixture();
        const read = local.read.getMockImplementation()!;
        local.read.mockImplementation(async (database, store, key) => {
            state.counts.stopped = 1;
            const value: unknown = await read(database, store, key);
            return value;
        });
        await expect(state.publish()).rejects.toThrow(
            'The participant authority changed during delivery.',
        );
        expect(state.send).not.toHaveBeenCalled();
        expect(state.reads).toEqual([
            recordKey(0, 0),
            recordKey(0, chunkBytes),
        ]);
    });
});
