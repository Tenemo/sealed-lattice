import { describe, expect, it, vi } from 'vitest';

import { publishReleaseRecords } from '#tools/ci/protocol-release-delivery.js';

// These are transport/state-ordering controls. Proof, signature and stored
// ciphertext authentication remain responsibilities of the owning callers.
const fixture = () => {
    const records = [
        Uint8Array.of(4),
        Uint8Array.of(5, 6, 7),
        Uint8Array.of(8),
    ];
    const copies: Uint8Array[] = [];
    return {
        envelope: Uint8Array.of(1, 2, 3),
        bodyRecordCount: records.length,
        readBody: vi.fn((index: number) => {
            const bytes = records[index].slice();
            copies.push(bytes);
            return Promise.resolve(bytes);
        }),
        copies,
    };
};
type Sent = ['envelope' | 'body', number, number[]];
const expected: Sent[] = [
    ['envelope', 0, [1, 2, 3]],
    ['body', 0, [4]],
    ['body', 1, [5, 6, 7]],
    ['body', 4, [8]],
];

describe('completed release delivery boundaries', () => {
    it('preserves unequal record lengths and exact bytes on repeated delivery', async () => {
        const state = fixture();
        const sent: Sent[] = [];
        const inspect = vi.fn(() => Promise.resolve());
        const send = (
            kind: 'envelope' | 'body',
            offset: number,
            bytes: Uint8Array,
        ) => {
            sent.push([kind, offset, Array.from(bytes)]);
            return Promise.resolve();
        };
        await publishReleaseRecords({ ...state, inspect, send });
        await publishReleaseRecords({ ...state, inspect, send });
        expect(sent).toEqual([...expected, ...expected]);
        expect(inspect).toHaveBeenCalledTimes(10);
        expect(
            state.copies.every((bytes) => bytes.every((byte) => byte === 0)),
        ).toBe(true);
        expect(state.envelope).toEqual(Uint8Array.of(1, 2, 3));
    });

    it('allows no later send after state loss at any successful send boundary', async () => {
        for (const lossAfter of [1, 2, 3, 4]) {
            const state = fixture();
            const sent: Sent[] = [];
            const inspect = () =>
                sent.length >= lossAfter
                    ? Promise.reject(new Error('Required root missing.'))
                    : Promise.resolve();
            await expect(
                publishReleaseRecords({
                    ...state,
                    inspect,
                    send: (kind, offset, bytes) => {
                        sent.push([kind, offset, Array.from(bytes)]);
                        return Promise.resolve();
                    },
                }),
            ).rejects.toThrow('Required root missing.');
            expect(sent).toEqual(expected.slice(0, lossAfter));
            expect(state.readBody).toHaveBeenCalledTimes(lossAfter - 1);
            expect(
                state.copies.every((bytes) =>
                    bytes.every((byte) => byte === 0),
                ),
            ).toBe(true);
        }
    });

    it('refuses damaged initial state before reading or sending any message', async () => {
        const state = fixture();
        const send = vi.fn(() => Promise.resolve());
        await expect(
            publishReleaseRecords({
                ...state,
                send,
                inspect: () =>
                    Promise.reject(new Error('Damaged local state.')),
            }),
        ).rejects.toThrow('Damaged local state.');
        expect(send).not.toHaveBeenCalled();
        expect(state.readBody).not.toHaveBeenCalled();
    });

    it('preserves a network error only when required state remains intact', async () => {
        for (const missing of [false, true]) {
            const state = fixture();
            const network = new Error('Network unavailable.');
            const local = new Error('Required record missing.');
            const send = vi.fn(() => Promise.reject(network));
            const inspect = () =>
                missing && send.mock.calls.length > 0
                    ? Promise.reject(local)
                    : Promise.resolve();
            await expect(
                publishReleaseRecords({ ...state, inspect, send }),
            ).rejects.toBe(missing ? local : network);
            expect(send).toHaveBeenCalledTimes(1);
            expect(state.readBody).not.toHaveBeenCalled();
        }
    });

    it('clears the outgoing body copy after a failed send', async () => {
        const state = fixture();
        await expect(
            publishReleaseRecords({
                ...state,
                inspect: () => Promise.resolve(),
                send: (kind) =>
                    kind === 'body'
                        ? Promise.reject(new Error('Delivery interrupted.'))
                        : Promise.resolve(),
            }),
        ).rejects.toThrow('Delivery interrupted.');
        expect(state.readBody).toHaveBeenCalledTimes(1);
        expect(state.copies[0]).toEqual(Uint8Array.of(0));
    });
});
