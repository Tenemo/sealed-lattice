import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';

import { expect, it } from 'vitest';

import { participantRelayWriter } from '#tools/ci/participant-relay-record.js';

it('serializes identical certificates and refuses other-origin extension or changed bytes', async () => {
    const scratch = path.resolve('temp');
    await mkdir(scratch, { recursive: true });
    const directory = await mkdtemp(path.join(scratch, 'participant-relay-'));
    try {
        const owners = new Map<string, string>();
        const write = participantRelayWriter(owners);
        const file = path.join(directory, 'setup-certificate.bin');
        const certificate = Buffer.from([1, 4, 7, 9]);
        expect(
            await Promise.all(
                Array.from({ length: 12 }, (_, index) =>
                    write(file, 'origin-' + String(index), 0, certificate),
                ),
            ),
        ).toEqual(Array.from({ length: 12 }, () => true));
        expect(await readFile(file)).toEqual(certificate);
        expect(owners.get(file)).toBe('origin-0');
        const competing = path.join(directory, 'competing-certificate.bin');
        const alternate = Buffer.from([1, 4, 8, 9]);
        expect(
            await Promise.all([
                write(competing, 'origin-a', 0, certificate),
                write(competing, 'origin-b', 0, alternate),
            ]),
        ).toEqual([true, false]);
        expect(await readFile(competing)).toEqual(certificate);
        expect(owners.get(competing)).toBe('origin-a');
        expect(await write(file, 'origin-1', 1, Buffer.from([4, 7]))).toBe(
            true,
        );
        expect(await write(file, 'origin-1', 4, Buffer.from([2]))).toBe(false);
        expect(await write(file, 'origin-1', 1, Buffer.from([4, 8]))).toBe(
            false,
        );
        expect(await write(file, 'origin-0', 3, Buffer.from([9, 2]))).toBe(
            false,
        );
        expect(await write(file, 'origin-0', 5, Buffer.from([2]))).toBe(false);
        expect(await write(file, 'origin-0', 4, Buffer.from([2]))).toBe(true);
        expect(
            await write(file, 'origin-2', 0, Buffer.from([1, 4, 7, 9, 2])),
        ).toBe(true);
        expect(await readFile(file)).toEqual(Buffer.from([1, 4, 7, 9, 2]));
        expect(owners.get(file)).toBe('origin-0');
    } finally {
        await rm(directory, { recursive: true });
    }
});
