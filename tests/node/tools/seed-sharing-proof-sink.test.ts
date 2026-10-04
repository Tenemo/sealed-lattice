import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { createSeedSharingProofSink } from '#tools/ci/seed-sharing-proof-sink.mjs';

const digest = (bytes: Uint8Array) =>
    createHash('sha512').update(bytes).digest('hex');
const fixture = async () => {
    await mkdir('temp', { recursive: true });
    const directory = await mkdtemp(path.resolve('temp/proof-sink-test-'));
    return { directory, file: path.join(directory, 'proof.data') };
};

describe('generated proof artifact writer', () => {
    it('exclusively creates its artifact and matches complete bytes before finishing', async () => {
        const files = await fixture();
        const bytes = new Uint8Array([1, 3, 5, 7]);
        const sink = await createSeedSharingProofSink(
            files.file,
            bytes.length,
            digest(bytes),
        );
        try {
            await expect(
                createSeedSharingProofSink(
                    files.file,
                    bytes.length,
                    digest(bytes),
                ),
            ).rejects.toMatchObject({ code: 'EEXIST' });
            expect(() => sink.finish()).toThrow('incomplete');
            expect(await sink.write(0, 0, bytes.subarray(0, 3))).toMatchObject({
                index: 0,
                offset: 0,
                length: 3,
                nextOffset: 3,
            });
            expect(() => sink.finish()).toThrow('incomplete');
            await sink.write(1, 3, bytes.subarray(3));
            expect(sink.finish()).toMatchObject({
                file: files.file,
                bytes: 4,
                sha512: digest(bytes),
            });
            expect(new Uint8Array(await readFile(files.file))).toEqual(bytes);
        } finally {
            await sink.close();
            await rm(files.directory, { recursive: true });
        }
    });
    it('refuses a mismatched complete digest permanently', async () => {
        const files = await fixture();
        const sink = await createSeedSharingProofSink(
            files.file,
            3,
            '0'.repeat(128),
        );
        try {
            await sink.write(0, 0, new Uint8Array([1, 2, 3]));
            expect(() => sink.finish()).toThrow('pinned identity');
            await expect(sink.write(1, 3, new Uint8Array([4]))).rejects.toThrow(
                'failed',
            );
            expect(() => sink.finish()).toThrow('completed output');
        } finally {
            await sink.close();
            await rm(files.directory, { recursive: true });
        }
    });
    it('fails a reentrant writer without queuing another chunk or acknowledging the first', async () => {
        const files = await fixture();
        const sink = await createSeedSharingProofSink(
            files.file,
            4,
            digest(new Uint8Array([1, 2, 3, 4])),
        );
        try {
            const pending = sink.write(0, 0, new Uint8Array([1, 2]));
            void pending.catch(() => undefined);
            await expect(
                sink.write(1, 2, new Uint8Array([3, 4])),
            ).rejects.toThrow('already writing');
            await expect(pending).rejects.toThrow('failed during');
            expect(sink.state()).toEqual({ bytes: 0, chunks: 0 });
            expect(() => sink.finish()).toThrow('completed output');
        } finally {
            await sink.close();
            await rm(files.directory, { recursive: true });
        }
    });
});
