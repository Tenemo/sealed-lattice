import { mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import path from 'node:path';

import { expect, it } from 'vitest';

import {
    candidateChunkBytes,
    decodeCandidateManifest,
    encodeCandidateManifest,
} from '#packages/sdk/src/participant/worker/candidate-codec.js';
import { guardDelivery } from '#packages/sdk/src/participant/worker/delivery.js';
import { PublicInputFailure } from '#packages/sdk/src/participant/worker/failures.js';
import {
    createCandidatePublication,
    findCandidate,
    readCandidateFile,
} from '#packages/sdk/src/participant/worker/public.js';
import { serveParticipantCandidates } from '#tools/ci/participant-candidate-http.js';
import { participantCandidateView } from '#tools/ci/participant-candidate-view.js';
import type { ViewedParticipantRecord } from '#tools/ci/participant-candidate-view.js';
import { participantRelayStore } from '#tools/ci/participant-relay-record.js';

const withStore = async (
    run: (
        directory: string,
        store: ReturnType<typeof participantRelayStore>,
    ) => Promise<void>,
) => {
    const scratch = path.resolve('temp');
    await mkdir(scratch, { recursive: true });
    const directory = await mkdtemp(path.join(scratch, 'participant-relay-'));
    try {
        await run(directory, participantRelayStore(directory));
    } finally {
        await rm(directory, { recursive: true });
    }
};

it('retains distinct immutable candidates through concurrent publication, pagination and restart', async () =>
    withStore(async (directory, store) => {
        const chunk = await store.putChunk(Uint8Array.of(3, 5, 7));
        const manifest = encodeCandidateManifest({
            files: [{ name: 'body.bin', length: 3, chunks: [chunk] }],
        });
        const receipts = await Promise.all(
            Array.from({ length: 69 }, () =>
                store.append('close-proposal', manifest),
            ),
        );
        expect(new Set(receipts.map((receipt) => receipt.id)).size).toBe(69);
        expect(
            receipts
                .map((receipt) => receipt.index)
                .sort((left, right) => left - right),
        ).toEqual(Array.from({ length: 69 }, (_, index) => index));
        const first = await store.page('close-proposal', 0);
        const rest = await participantRelayStore(directory).page(
            'close-proposal',
            first.ids.length,
        );
        expect(first.ids).toHaveLength(64);
        expect(rest.ids).toHaveLength(5);
        expect(first.total).toBe(69);
        expect(rest.total).toBe(69);
        expect(new Set([...first.ids, ...rest.ids])).toEqual(
            new Set(receipts.map((receipt) => receipt.id)),
        );
        const original = await store.file(receipts[0].id, 'body.bin');
        await store.putChunk(Uint8Array.of(9, 9, 9));
        const bytes = [];
        for await (const part of original.read()) bytes.push(part);
        expect(Buffer.concat(bytes)).toEqual(Buffer.from([3, 5, 7]));
    }));

it('selects and hides equivocal candidate discovery without changing the immutable publications', async () =>
    withStore(async (directory, store) => {
        const projection = participantCandidateView(store, directory);
        const candidates = [];
        for (const value of [17, 23, 41]) {
            const envelope = await store.putChunk(Uint8Array.of(value, 5));
            const body = await store.putChunk(Uint8Array.of(value));
            const receipt = await store.append(
                'ballot-1',
                encodeCandidateManifest({
                    files: [
                        { name: 'envelope.bin', length: 2, chunks: [envelope] },
                        { name: 'body.bin', length: 1, chunks: [body] },
                    ],
                }),
            );
            const candidate = await store.candidate(receipt.id);
            await projection.published(candidate);
            candidates.push({
                candidate,
                identity: await readFile(
                    path.join(directory, 'ballot-1/submission.bin'),
                ),
                value,
            });
        }
        const view = new Map<string, ViewedParticipantRecord>();
        const reader = projection.forReader(view, () => undefined);
        const all = {
            total: 3,
            ids: candidates.map(({ candidate }) => candidate.id),
        };
        expect(await reader.page('ballot-1', 0)).toEqual(all);
        expect(
            new Set(candidates.map(({ identity }) => identity.toString('hex')))
                .size,
        ).toBe(3);
        for (const { candidate, identity, value } of candidates) {
            view.set('ballot-1/submission.bin', identity);
            expect(await reader.page('ballot-1', 0)).toEqual({
                total: 1,
                ids: [candidate.id],
            });
            expect(await reader.page('ballot-1', 1)).toEqual({
                total: 1,
                ids: [],
            });
            expect(await reader.manifest(candidate)).toEqual(
                new Uint8Array(candidate.bytes),
            );
            const body = [];
            for await (const bytes of (
                await store.file(candidate.id, 'body.bin')
            ).read())
                body.push(bytes);
            expect(Buffer.concat(body)).toEqual(Buffer.of(value));
        }
        view.set('ballot-1/submission.bin', undefined);
        expect(await reader.page('ballot-1', 0)).toEqual({ total: 0, ids: [] });
        expect(await store.page('ballot-1', 0)).toEqual(all);
        view.delete('ballot-1/submission.bin');
        expect(await reader.page('ballot-1', 0)).toEqual(all);
        const shared = candidates[0].candidate.manifest.files.find(
            (file) => file.name === 'body.bin',
        )!.chunks[0];
        const closureReceipt = await store.append(
            'close-proposal',
            encodeCandidateManifest({
                files: [{ name: 'body.bin', length: 1, chunks: [shared] }],
            }),
        );
        const closure = await store.candidate(closureReceipt.id);
        await projection.published(closure);
        view.set('close/closure/body.bin', undefined);
        expect(await reader.manifest(closure)).toBeUndefined();
        expect(
            Buffer.from(
                (await reader.chunk(shared, await store.chunk(shared))) ?? [],
            ),
        ).toEqual(Buffer.of(17));
        view.set('close/closure/body.bin', Buffer.of(99));
        const changed = decodeCandidateManifest(
            (await reader.manifest(closure))!,
        );
        const changedId = changed.files[0].chunks[0];
        expect(changedId).not.toBe(shared);
        expect(await store.chunk(changedId)).toEqual(Buffer.of(99));
        expect(
            Buffer.from(
                (await reader.chunk(shared, await store.chunk(shared))) ?? [],
            ),
        ).toEqual(Buffer.of(17));
    }));

it('never appends a manifest whose immutable chunks are missing or incomplete', async () =>
    withStore(async (_directory, store) => {
        const empty = await store.putChunk(new Uint8Array());
        const short = await store.putChunk(Uint8Array.of(1));
        for (const id of ['f'.repeat(32), empty, short]) {
            await expect(
                store.append(
                    'poll',
                    encodeCandidateManifest({
                        files: [
                            { name: 'definition.bin', length: 2, chunks: [id] },
                        ],
                    }),
                ),
            ).rejects.toThrow();
            expect(await store.page('poll', 0)).toEqual({ total: 0, ids: [] });
        }
        const complete = await store.putChunk(Uint8Array.of(1, 2));
        const receipt = await store.append(
            'poll',
            encodeCandidateManifest({
                files: [
                    { name: 'definition.bin', length: 2, chunks: [complete] },
                ],
            }),
        );
        expect(receipt.index).toBe(0);
    }));

it('allows later original bytes after junk and empty publications without first-writer ownership', async () =>
    withStore(async (_directory, store) => {
        const server = createServer((request, response) => {
            const url = new URL(request.url ?? '/', 'http://127.0.0.1');
            serveParticipantCandidates(store, request, response, url)
                .then((handled) => {
                    if (!handled) response.writeHead(404).end();
                })
                .catch(() => response.writeHead(500).end());
        });
        await new Promise<void>((resolve) =>
            server.listen(0, '127.0.0.1', resolve),
        );
        const address = server.address();
        if (address === null || typeof address === 'string')
            throw new Error('Missing test address.');
        const relay = { base: `http://127.0.0.1:${String(address.port)}/` };
        try {
            const delivery = await guardDelivery(() => Promise.resolve());
            for (const key of [
                'poll',
                'registration/' + 'ab'.repeat(64),
                'contribution-1/' + 'cd'.repeat(64),
                'close-proposal',
                'target-vote-1',
                'release-2',
            ]) {
                for (const bytes of [new Uint8Array(), Uint8Array.of(255)]) {
                    const junk = createCandidatePublication(
                        relay,
                        key,
                        delivery,
                    );
                    await junk.addBytes('body.bin', bytes);
                    await junk.finish();
                }
                const expected = Uint8Array.from(
                    { length: candidateChunkBytes + 19 },
                    (_, index) => index % 251,
                );
                const changed = createCandidatePublication(
                    relay,
                    key,
                    delivery,
                );
                await changed.addBytes(
                    'body.bin',
                    new Uint8Array(expected.length),
                );
                await changed.finish();
                const original = createCandidatePublication(
                    relay,
                    key,
                    delivery,
                );
                await original.addStream(
                    'body.bin',
                    expected.length,
                    async (accept) => {
                        for (
                            let offset = 0;
                            offset < expected.length;
                            offset += 4093
                        )
                            await accept(expected.slice(offset, offset + 4093));
                    },
                );
                await original.addBytes('signature.bin', Uint8Array.of(7, 11));
                await original.finish();
                let refused = 0;
                const received = await findCandidate(
                    relay,
                    key,
                    async (candidate) => {
                        const bytes = await readCandidateFile(
                            relay,
                            candidate,
                            'body.bin',
                            expected.length,
                        );
                        if (!Buffer.from(bytes).equals(Buffer.from(expected))) {
                            refused++;
                            throw new PublicInputFailure(
                                'Wrong original bytes.',
                            );
                        }
                        expect(
                            await readCandidateFile(
                                relay,
                                candidate,
                                'signature.bin',
                                2,
                            ),
                        ).toEqual(Uint8Array.of(7, 11));
                        return bytes;
                    },
                );
                expect(refused).toBe(3);
                // Generic deep equality visits each of the 1 MiB elements
                // separately and takes over a second per comparison.
                expect(
                    Buffer.from(received).equals(Buffer.from(expected)),
                ).toBe(true);

                const before = await readdir(path.join(_directory, 'chunks'));
                const retainedCopies: Uint8Array[] = [];
                const forwarding = createCandidatePublication(
                    relay,
                    key + '/forwarded',
                    delivery,
                );
                await forwarding.addRetainedFile(
                    'body.bin',
                    expected.length,
                    async (accept) => {
                        for (
                            let offset = 0;
                            offset < expected.length;
                            offset += 4093
                        ) {
                            const copy = expected.slice(offset, offset + 4093);
                            retainedCopies.push(copy);
                            await accept(copy);
                        }
                    },
                    key,
                    'body.bin',
                );
                await forwarding.finish();
                expect(await readdir(path.join(_directory, 'chunks'))).toEqual(
                    before,
                );
                expect(
                    retainedCopies.every((bytes) =>
                        bytes.every((byte) => byte === 0),
                    ),
                ).toBe(true);
                const forwarded = await findCandidate(
                    relay,
                    key + '/forwarded',
                    (candidate) =>
                        readCandidateFile(
                            relay,
                            candidate,
                            'body.bin',
                            expected.length,
                        ),
                );
                expect(
                    Buffer.from(forwarded).equals(Buffer.from(expected)),
                ).toBe(true);
            }
            const retained = Uint8Array.of(3, 17, 127, 255);
            const beforeCopy = await readdir(path.join(_directory, 'chunks'));
            const missing = createCandidatePublication(
                relay,
                'retained-body-copy',
                delivery,
            );
            await missing.addRetainedFile(
                'body.bin',
                retained.length,
                (accept) => accept(retained.slice()),
                'missing-body',
                'body.bin',
            );
            await missing.finish();
            expect(
                (await readdir(path.join(_directory, 'chunks'))).length,
            ).toBe(beforeCopy.length + 1);
            expect(
                await findCandidate(relay, 'retained-body-copy', (candidate) =>
                    readCandidateFile(
                        relay,
                        candidate,
                        'body.bin',
                        retained.length,
                    ),
                ),
            ).toEqual(retained);
            for (const route of [
                'chunks?extra=1',
                'candidates/poll?offset=-1',
                'candidates/poll?offset=0&offset=1',
                'chunk/' + '../private',
            ]) {
                const response = await fetch(relay.base + route);
                expect(response.ok).toBe(false);
            }
        } finally {
            server.closeAllConnections();
            await new Promise<void>((resolve, reject) =>
                server.close((error) =>
                    error === undefined ? resolve() : reject(error),
                ),
            );
        }
    }));
