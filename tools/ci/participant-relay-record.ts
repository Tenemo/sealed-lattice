import { randomBytes } from 'node:crypto';
import { mkdir, open, readdir, readFile, rename, stat } from 'node:fs/promises';
import path from 'node:path';

import {
    candidateChunkBytes,
    candidateIdentifierBytes,
    candidatePageEntries,
    decodeCandidateManifest,
    isCandidateId,
    isCandidateKey,
    type CandidateManifest,
} from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';

export type StoredParticipantCandidate = Readonly<{
    id: string;
    key: string;
    manifest: CandidateManifest;
    bytes: Buffer;
}>;

// This transport never interprets protocol identities, signatures or proofs.
// Every completed upload gets a new locator. Only complete candidate objects
// enter a logical key's append-only discovery log; earlier bytes reserve no key.
export const participantRelayStore = (directory: string) => {
    const pending = new Map<string, Promise<void>>();
    const locked = async <Value>(key: string, action: () => Promise<Value>) => {
        const previous = pending.get(key);
        let unlock!: () => void;
        const released = new Promise<void>((resolve) => {
            unlock = resolve;
        });
        pending.set(key, released);
        await previous;
        try {
            return await action();
        } finally {
            if (pending.get(key) === released) pending.delete(key);
            unlock();
        }
    };
    const objectDirectory = (kind: string, id: string) => {
        if (!isCandidateId(id)) throw new Error('Invalid transport locator.');
        return path.join(directory, kind, id);
    };
    const allocate = async (kind: string) => {
        await mkdir(path.join(directory, kind), { recursive: true });
        for (;;) {
            const id = randomBytes(candidateIdentifierBytes).toString('hex');
            const target = objectDirectory(kind, id);
            try {
                await mkdir(target);
                return { id, target };
            } catch (error) {
                if (
                    error === null ||
                    typeof error !== 'object' ||
                    !('code' in error) ||
                    error.code !== 'EEXIST'
                )
                    throw error;
            }
        }
    };
    const durableFile = async (file: string, bytes: Uint8Array) => {
        const temporary =
            file +
            '.pending-' +
            randomBytes(candidateIdentifierBytes).toString('hex');
        const handle = await open(temporary, 'wx');
        try {
            await handle.writeFile(bytes);
            await handle.sync();
        } finally {
            await handle.close();
        }
        await rename(temporary, file);
    };
    const entriesDirectory = (key: string) => {
        if (!isCandidateKey(key)) throw new Error('Invalid candidate key.');
        return path.join(
            directory,
            'keys',
            ...Buffer.from(key)
                .toString('hex')
                .match(/.{1,120}/gu)!,
            'entries',
        );
    };
    const entryName = (index: number) =>
        String(index).padStart(16, '0') + '.bin';
    const entries = async (key: string) => {
        const target = entriesDirectory(key);
        const names = await readdir(target).catch((error: unknown) => {
            if (
                error !== null &&
                typeof error === 'object' &&
                'code' in error &&
                error.code === 'ENOENT'
            )
                return [];
            throw error;
        });
        const complete = names
            .filter((name) => /^\d{16}\.bin$/u.test(name))
            .sort();
        if (complete.some((name, index) => name !== entryName(index)))
            throw new Error('The candidate discovery prefix is incomplete.');
        return { target, complete };
    };
    const candidate = async (
        id: string,
    ): Promise<StoredParticipantCandidate> => {
        const target = objectDirectory('candidates', id);
        const [bytes, key] = await Promise.all([
            readFile(path.join(target, 'manifest.bin')),
            readFile(path.join(target, 'key.txt'), 'utf8'),
        ]);
        if (!isCandidateKey(key))
            throw new Error('Invalid stored candidate key.');
        return { id, key, bytes, manifest: decodeCandidateManifest(bytes) };
    };
    const chunk = async (id: string) => {
        const file = path.join(objectDirectory('chunks', id), 'body.bin');
        const size = (await stat(file)).size;
        if (size > candidateChunkBytes)
            throw new Error('A stored chunk exceeds its transport bound.');
        return readFile(file);
    };
    return {
        putChunk: async (bytes: Uint8Array) => {
            if (bytes.length > candidateChunkBytes)
                throw new Error('A publication chunk exceeds its bound.');
            const { id, target } = await allocate('chunks');
            await durableFile(path.join(target, 'body.bin'), bytes);
            return id;
        },
        chunk,
        append: async (key: string, bytes: Uint8Array) => {
            if (!isCandidateKey(key)) throw new Error('Invalid candidate key.');
            const manifest = decodeCandidateManifest(bytes);
            for (const file of manifest.files) {
                let remaining = file.length;
                for (const locator of file.chunks) {
                    const length = (
                        await stat(
                            path.join(
                                objectDirectory('chunks', locator),
                                'body.bin',
                            ),
                        )
                    ).size;
                    if (length !== Math.min(candidateChunkBytes, remaining))
                        throw new RangeError(
                            'A candidate chunk has the wrong length.',
                        );
                    remaining -= length;
                }
            }
            const { id, target } = await allocate('candidates');
            await durableFile(path.join(target, 'key.txt'), Buffer.from(key));
            await durableFile(path.join(target, 'manifest.bin'), bytes);
            return locked(key, async () => {
                const { target: log, complete } = await entries(key);
                await mkdir(log, { recursive: true });
                const index = complete.length;
                await durableFile(
                    path.join(log, entryName(index)),
                    Buffer.from(id, 'hex'),
                );
                return { id, index };
            });
        },
        candidate,
        page: async (key: string, offset: number) => {
            if (!Number.isSafeInteger(offset) || offset < 0)
                throw new Error('Invalid candidate discovery cursor.');
            return locked(key, async () => {
                const { target, complete } = await entries(key);
                const names = complete.slice(
                    offset,
                    offset + candidatePageEntries,
                );
                const ids = await Promise.all(
                    names.map(async (name) => {
                        const value = await readFile(path.join(target, name));
                        if (value.length !== candidateIdentifierBytes)
                            throw new Error(
                                'A candidate discovery entry is incomplete.',
                            );
                        return value.toString('hex');
                    }),
                );
                return { total: complete.length, ids };
            });
        },
        file: async (id: string, name: string) => {
            const stored = await candidate(id);
            const file = stored.manifest.files.find(
                (entry) => entry.name === name,
            );
            if (file === undefined) throw new Error('No named candidate file.');
            return {
                candidate: stored,
                length: file.length,
                read: async function* () {
                    let remaining = file.length;
                    for (const locator of file.chunks) {
                        const bytes = await chunk(locator);
                        if (
                            bytes.length !==
                            Math.min(candidateChunkBytes, remaining)
                        )
                            throw new Error(
                                'A candidate chunk has the wrong length.',
                            );
                        remaining -= bytes.length;
                        yield bytes;
                    }
                    if (remaining !== 0)
                        throw new Error('A candidate file is incomplete.');
                },
            };
        },
    };
};
