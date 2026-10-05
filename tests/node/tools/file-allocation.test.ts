import { link, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { expect, it } from 'vitest';

import { sampleFileAllocation } from '#tools/ci/file-allocation.js';

it('measures file lengths and allocated storage including database files and reports missing paths and hard links', async () => {
    const directory = await mkdtemp(path.resolve('temp/file-allocation-'));
    try {
        const database = path.join(directory, 'Default', 'IndexedDB');
        await mkdir(database, { recursive: true });
        await writeFile(
            path.join(directory, 'profile.bin'),
            Buffer.alloc(8193, 3),
        );
        await writeFile(
            path.join(database, 'journal.bin'),
            Buffer.alloc(4097, 7),
        );
        await link(
            path.join(directory, 'profile.bin'),
            path.join(directory, 'linked.bin'),
        );
        const [total, missing] = await sampleFileAllocation([
            directory,
            path.join(directory, 'absent'),
        ]);
        expect(total.files).toBe(3);
        expect(total.fileBytes).toBe(2 * 8193 + 4097);
        expect(total.indexedDatabaseFileBytes).toBe(4097);
        expect(total.allocatedBytes).toBeGreaterThanOrEqual(total.fileBytes);
        expect(total.indexedDatabaseAllocatedBytes).toBeGreaterThanOrEqual(
            4097,
        );
        expect(total.multiplyLinkedFiles).toBe(2);
        expect(
            total.missingEntries + total.unreadableEntries + total.skippedLinks,
        ).toBe(0);
        expect(missing.missingEntries).toBe(1);
        expect(missing.files).toBe(0);
        expect(await sampleFileAllocation([])).toEqual([]);
    } finally {
        await rm(directory, { recursive: true });
    }
});
