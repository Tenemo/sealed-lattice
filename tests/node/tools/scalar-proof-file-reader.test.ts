import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { expect, it } from 'vitest';

import { withPinnedProofReaders } from '#tools/ci/scalar-proof-file-reader.mjs';

it('reads separate pinned streams within one bounded input buffer and refuses invalid spans', async () => {
    await mkdir('temp', { recursive: true });
    const directory = await mkdtemp(path.resolve('temp/scalar-proof-reader-'));
    try {
        const inputs = [
            Buffer.alloc((1 << 20) + 3, 17),
            Buffer.from([29, 31, 37]),
        ];
        const proofs = await Promise.all(
            inputs.map(async (bytes, index) => {
                const file = path.join(directory, String(index));
                await writeFile(file, bytes);
                return {
                    file,
                    bytes: bytes.length,
                    sha512: createHash('sha512').update(bytes).digest('hex'),
                };
            }),
        );
        await withPinnedProofReaders(proofs, async (read) => {
            expect((await read(0, 1 << 20, 0)).byteLength).toBe(1 << 20);
            expect(Array.from(await read(0, 3, 1 << 20))).toEqual([17, 17, 17]);
            expect(Array.from(await read(1, 2, 1))).toEqual([31, 37]);
            await expect(read(0, (1 << 20) + 1, 0)).rejects.toThrow(
                'pinned bound',
            );
            await expect(read(1, 3, 1)).rejects.toThrow('pinned bound');
            await expect(read(2, 1, 0)).rejects.toThrow('pinned bound');
        });
        await expect(
            withPinnedProofReaders(proofs, () =>
                Promise.reject(new Error('host failure')),
            ),
        ).rejects.toThrow('host failure');
        await expect(
            withPinnedProofReaders(
                [{ ...proofs[0], sha512: '0'.repeat(128) }],
                () => Promise.resolve(),
            ),
        ).rejects.toThrow();
        await expect(
            withPinnedProofReaders(proofs, async () => {
                await writeFile(proofs[1].file, Buffer.from([29, 31, 38]));
            }),
        ).rejects.toThrow();
    } finally {
        await rm(directory, { recursive: true });
    }
});
