import { createHash } from 'node:crypto';
import { mkdir, open, readFile } from 'node:fs/promises';
import path from 'node:path';

import {
    candidateChunkBytes,
    candidatePageEntries,
    decodeCandidateManifest,
    encodeCandidateManifest,
} from '#packages/sdk/src/participant/worker/candidate-codec.js';
import type {
    participantRelayStore,
    StoredParticipantCandidate,
} from '#tools/ci/participant-relay-record.js';

export type ViewedParticipantRecord =
    | Buffer
    | Readonly<{ file: string; beforeServe?: () => Promise<void> }>
    | undefined;
type Store = ReturnType<typeof participantRelayStore>;

// Offline diagnostic names and fault-injection coordinates. These copies
// are never served as protocol records: the worker reads candidate manifests
// and immutable chunks, and only its Rust verifiers authenticate their bytes.
const identity = (domain: string, bytes: Uint8Array) => {
    const purpose = Buffer.from(domain);
    const item = (type: number, value: Buffer) => {
        const prefix = Buffer.alloc(10);
        prefix.writeUInt16LE(type);
        prefix.writeUInt32LE(value.length + 4, 2);
        prefix.writeUInt32LE(value.length, 6);
        return Buffer.concat([prefix, value]);
    };
    const header = Buffer.alloc(8);
    header.writeUInt16LE(1);
    header.writeUInt16LE(1, 2);
    header.writeUInt32LE(2, 4);
    return createHash('shake256', { outputLength: 64 })
        .update(header)
        .update(item(2, purpose))
        .update(item(1, Buffer.from(bytes)))
        .digest();
};

export const participantCandidateView = (store: Store, directory: string) => {
    const paths = new Map<string, Map<string, string>>();
    const chunkLocations = new Map<string, { route: string; offset: number }>();
    const ballotIdentities = new Map<string, string>();
    const readSmall = async (
        candidate: StoredParticipantCandidate,
        name: string,
        maximum: number,
    ) => {
        const metadata = candidate.manifest.files.find(
            (file) => file.name === name,
        );
        if (metadata === undefined || metadata.length > maximum)
            return undefined;
        const pieces = [];
        for (const id of metadata.chunks) pieces.push(await store.chunk(id));
        const bytes = Buffer.concat(pieces);
        return bytes.length === metadata.length ? bytes : undefined;
    };
    const project = async (candidate: StoredParticipantCandidate) => {
        const mapped = paths.get(candidate.id);
        if (mapped !== undefined) return mapped;
        const key = candidate.key;
        const ballot = /^ballot-\d+$/u.test(key)
            ? await readSmall(candidate, 'envelope.bin', 4096)
            : undefined;
        const envelopeIdentity =
            ballot === undefined
                ? undefined
                : identity(
                      'sealed-lattice/ballot-envelope-id/v1',
                      ballot,
                  ).toString('hex');
        if (envelopeIdentity !== undefined && candidate.id !== '')
            ballotIdentities.set(candidate.id, envelopeIdentity);
        const result = new Map(
            candidate.manifest.files.map((file) => {
                let route = key + '/' + file.name;
                if (key === 'poll')
                    route =
                        file.name === 'definition.bin'
                            ? 'poll-definition.bin'
                            : 'poll-signature.bin';
                else if (key === 'roster')
                    route =
                        file.name === 'proposal.bin'
                            ? 'proposal.bin'
                            : 'proposal-signature.bin';
                else if (key === 'selection')
                    route =
                        file.name === 'selection.bin'
                            ? 'selection.bin'
                            : 'selection-signature.bin';
                else if (/^selection-endorsement-\d+$/u.test(key))
                    route = key + '.bin';
                else if (key === 'setup-certificate')
                    route = 'setup-certificate.bin';
                else if (envelopeIdentity !== undefined)
                    route = key + '/' + envelopeIdentity + '/' + file.name;
                else if (key === 'close-intent') route = 'close/intent.bin';
                else if (/^close-response-\d+$/u.test(key)) {
                    const position = key.slice('close-response-'.length);
                    route =
                        'close/response-' +
                        position +
                        (file.name === 'response.bin'
                            ? '.bin'
                            : file.name === 'submissions.bin'
                              ? '-submissions.bin'
                              : '-' + file.name);
                } else if (key === 'close-proposal')
                    route =
                        file.name === 'proposal.bin'
                            ? 'close/proposal.bin'
                            : file.name === 'intent.bin'
                              ? 'close/intent.bin'
                              : 'close/closure/' + file.name;
                else if (/^target-vote-\d+$/u.test(key))
                    route =
                        'completion/' +
                        (file.name === 'target.bin'
                            ? 'target.bin'
                            : key + '.bin');
                else if (/^release-\d+$/u.test(key))
                    route =
                        'completion/' +
                        (file.name === 'body.bin'
                            ? key
                            : 'release-envelope-' +
                              key.slice('release-'.length)) +
                        '.bin';
                if (candidate.id !== '')
                    file.chunks.forEach((id, index) =>
                        chunkLocations.set(id, {
                            route,
                            offset: index * candidateChunkBytes,
                        }),
                    );
                return [file.name, route] as const;
            }),
        );
        if (candidate.id !== '') paths.set(candidate.id, result);
        return result;
    };
    const viewedBytes = async (value: ViewedParticipantRecord) => {
        if (value === undefined || Buffer.isBuffer(value)) return value;
        await value.beforeServe?.();
        return readFile(value.file);
    };
    return {
        accepts: async (
            key: string,
            bytes: Uint8Array,
            refused: ReadonlySet<string>,
        ) => {
            const mapped = await project({
                id: '',
                key,
                bytes: Buffer.from(bytes),
                manifest: decodeCandidateManifest(bytes),
            });
            return ![...mapped.values()].some((route) => refused.has(route));
        },
        published: async (candidate: StoredParticipantCandidate) => {
            const mapped = await project(candidate);
            for (const [name, route] of mapped) {
                const destination = path.join(directory, route);
                await mkdir(path.dirname(destination), { recursive: true });
                const handle = await open(destination, 'w');
                try {
                    for await (const bytes of (
                        await store.file(candidate.id, name)
                    ).read())
                        await handle.writeFile(bytes);
                } finally {
                    await handle.close();
                }
            }
            const ballotIdentity = ballotIdentities.get(candidate.id);
            if (ballotIdentity !== undefined) {
                const handle = await open(
                    path.join(directory, candidate.key, 'submission.bin'),
                    'w',
                );
                try {
                    await handle.writeFile(Buffer.from(ballotIdentity, 'hex'));
                } finally {
                    await handle.close();
                }
            }
            if (candidate.key === 'setup-certificate') {
                const bytes = await readSmall(
                    candidate,
                    'certificate.bin',
                    1 << 20,
                );
                if (
                    bytes !== undefined &&
                    bytes.length >= 8 &&
                    bytes.subarray(0, 4).toString() === 'SSC1'
                ) {
                    const length = bytes.readUInt32LE(4);
                    if (length <= bytes.length - 8) {
                        const handle = await open(
                            path.join(directory, 'setup-identity.bin'),
                            'w',
                        );
                        try {
                            await handle.writeFile(
                                identity(
                                    'sealed-lattice/setup-selection-id/v1',
                                    bytes.subarray(8, 8 + length),
                                ),
                            );
                        } finally {
                            await handle.close();
                        }
                    }
                }
            }
        },
        forReader: (
            view: ReadonlyMap<string, ViewedParticipantRecord>,
            served: (route: string, bytes: number) => void,
        ) => ({
            page: async (key: string, offset: number) => {
                const pointer = key + '/submission.bin';
                if (!/^ballot-\d+$/u.test(key) || !view.has(pointer))
                    return store.page(key, offset);
                const selected = await viewedBytes(view.get(pointer));
                if (selected === undefined) return { total: 0, ids: [] };
                const ids = [];
                let total = 0;
                let end: number | undefined;
                do {
                    const page = await store.page(key, total);
                    end ??= page.total;
                    const visible = page.ids.slice(0, end - total);
                    for (const id of visible) {
                        await project(await store.candidate(id));
                        if (
                            ballotIdentities.get(id) ===
                            selected.toString('hex')
                        )
                            ids.push(id);
                    }
                    total += visible.length;
                    if (visible.length === 0) break;
                } while (total < end);
                return {
                    total: ids.length,
                    ids: ids.slice(offset, offset + candidatePageEntries),
                };
            },
            manifest: async (candidate: StoredParticipantCandidate) => {
                const mapped = await project(candidate);
                const files = [];
                for (const file of candidate.manifest.files) {
                    const route = mapped.get(file.name)!;
                    if (!view.has(route)) {
                        files.push(file);
                        continue;
                    }
                    const bytes = await viewedBytes(view.get(route));
                    if (bytes === undefined) continue;
                    const chunks = [];
                    for (
                        let offset = 0;
                        offset < bytes.length;
                        offset += candidateChunkBytes
                    ) {
                        const id = await store.putChunk(
                            bytes.subarray(
                                offset,
                                offset + candidateChunkBytes,
                            ),
                        );
                        chunkLocations.set(id, { route, offset });
                        chunks.push(id);
                    }
                    files.push({
                        name: file.name,
                        length: bytes.length,
                        chunks,
                    });
                }
                return files.length === 0
                    ? undefined
                    : encodeCandidateManifest({ files });
            },
            chunk: async (id: string, original: Uint8Array) => {
                const location = chunkLocations.get(id);
                if (location === undefined) return original;
                const { route, offset } = location;
                const overridden = view.has(route);
                const bytes = overridden
                    ? await viewedBytes(view.get(route))
                    : original;
                if (bytes === undefined) return undefined;
                const output = overridden
                    ? bytes.subarray(offset, offset + candidateChunkBytes)
                    : bytes;
                served(route, output.length);
                return output;
            },
        }),
    };
};
