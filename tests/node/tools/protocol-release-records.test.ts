import { describe, expect, it, vi } from 'vitest';

import { verifyReleaseRecords } from '#tools/ci/protocol-release-records.js';

const configuration = { recordBytes: 32, totalRandomBytes: 49 };
const state = {
    journalKeys: [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)],
    bodyKeys: [new Uint8Array(32).fill(3), new Uint8Array(32).fill(4)],
    bodyLength: 37,
};

describe('required release-record inspection', () => {
    it('reads every journal and partial body record and clears returned plaintext', async () => {
        const plaintext: Uint8Array[] = [];
        const records = {
            count: vi.fn(() => Promise.resolve(4)),
            read: vi.fn(
                (
                    _kind: number,
                    _index: number,
                    _key: Uint8Array,
                    length: number,
                ) => {
                    const bytes = new Uint8Array(length).fill(7);
                    plaintext.push(bytes);
                    return Promise.resolve(bytes);
                },
            ),
        };
        await verifyReleaseRecords(state, configuration, records);
        expect(records.read.mock.calls).toEqual([
            [0, 0, state.journalKeys[0], 32],
            [0, 1, state.journalKeys[1], 17],
            [1, 0, state.bodyKeys[0], 32],
            [1, 1, state.bodyKeys[1], 5],
        ]);
        expect(
            plaintext.every((bytes) => bytes.every((value) => value === 0)),
        ).toBe(true);
        expect(state.journalKeys[0].every((value) => value === 1)).toBe(true);
    });

    it('refuses missing and extra records before reading or accepting state', async () => {
        for (const count of [0, 3, 5]) {
            const records = {
                count: () => Promise.resolve(count),
                read: vi.fn(() => Promise.resolve(new Uint8Array())),
            };
            await expect(
                verifyReleaseRecords(state, configuration, records),
            ).rejects.toThrow('Release record inventory changed.');
            expect(records.read).not.toHaveBeenCalled();
        }
        const records = {
            count: () => Promise.resolve(0),
            read: vi.fn(() => Promise.resolve(new Uint8Array())),
        };
        await verifyReleaseRecords(undefined, configuration, records);
        expect(records.read).not.toHaveBeenCalled();
    });

    it('propagates authentication failures and stops at the damaged record', async () => {
        const first = new Uint8Array(32).fill(9);
        const failure = new Error('Authenticated record is damaged.');
        const records = {
            count: () => Promise.resolve(4),
            read: vi
                .fn()
                .mockResolvedValueOnce(first)
                .mockRejectedValue(failure),
        };
        await expect(
            verifyReleaseRecords(state, configuration, records),
        ).rejects.toBe(failure);
        expect(records.read).toHaveBeenCalledTimes(2);
        expect(first.every((value) => value === 0)).toBe(true);
    });
});
