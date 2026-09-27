import { describe, expect, it, vi } from 'vitest';

import { guardDelivery } from '#packages/sdk/src/participant/worker/delivery.js';

// Transport and ordering controls of a completed message's delivery. Record
// and root authentication belong to the inspection, which the browser test
// exercises against real IndexedDB records.
const fixture = () => {
    const records = [
        Uint8Array.of(4),
        Uint8Array.of(5, 6, 7),
        Uint8Array.of(8),
    ];
    const copies: Uint8Array[] = [];
    return {
        envelope: Uint8Array.of(1, 2, 3),
        readBody: vi.fn((index: number) => {
            const bytes = records[index].slice();
            copies.push(bytes);
            return Promise.resolve(bytes);
        }),
        copies,
        count: records.length,
    };
};
type Sent = ['body' | 'envelope', number, number[]];
const expected: Sent[] = [
    ['body', 0, [4]],
    ['body', 1, [5, 6, 7]],
    ['body', 4, [8]],
    ['envelope', 0, [1, 2, 3]],
];

// Delivers the body records and then the envelope, as a release does.
const deliver = async (
    state: ReturnType<typeof fixture>,
    inspect: () => Promise<void>,
    send: (kind: Sent[0], offset: number, bytes: Uint8Array) => Promise<void>,
) => {
    const delivery = await guardDelivery(inspect);
    let offset = 0;
    for (let index = 0; index < state.count; index++) {
        const bytes = await state.readBody(index);
        const at = offset;
        await delivery.transfer(() => send('body', at, bytes), bytes);
        offset += bytes.length;
    }
    await delivery.transfer(() => send('envelope', 0, state.envelope));
};

describe('completed message delivery', () => {
    it('sends every part in order, inspects around each transfer and clears every read copy', async () => {
        const state = fixture();
        const sent: Sent[] = [];
        const inspect = vi.fn(() => Promise.resolve());
        const send = (kind: Sent[0], offset: number, bytes: Uint8Array) => {
            sent.push([kind, offset, Array.from(bytes)]);
            return Promise.resolve();
        };
        await deliver(state, inspect, send);
        await deliver(state, inspect, send);
        expect(sent).toEqual([...expected, ...expected]);
        expect(inspect).toHaveBeenCalledTimes(2 * (1 + expected.length));
        expect(
            state.copies.every((bytes) => bytes.every((byte) => byte === 0)),
        ).toBe(true);
        expect(state.envelope).toEqual(Uint8Array.of(1, 2, 3));
    });

    it('reads and sends nothing after state loss at any successful transfer', async () => {
        for (const lossAfter of [1, 2, 3, 4]) {
            const state = fixture();
            const sent: Sent[] = [];
            const inspect = () =>
                sent.length >= lossAfter
                    ? Promise.reject(new Error('Required root missing.'))
                    : Promise.resolve();
            await expect(
                deliver(state, inspect, (kind, offset, bytes) => {
                    sent.push([kind, offset, Array.from(bytes)]);
                    return Promise.resolve();
                }),
            ).rejects.toThrow('Required root missing.');
            expect(sent).toEqual(expected.slice(0, lossAfter));
            expect(state.readBody).toHaveBeenCalledTimes(
                Math.min(lossAfter, state.count),
            );
            expect(
                state.copies.every((bytes) =>
                    bytes.every((byte) => byte === 0),
                ),
            ).toBe(true);
        }
    });

    it('refuses damaged initial state before reading or sending anything', async () => {
        const state = fixture();
        const send = vi.fn(() => Promise.resolve());
        await expect(
            deliver(
                state,
                () => Promise.reject(new Error('Damaged local state.')),
                send,
            ),
        ).rejects.toThrow('Damaged local state.');
        expect(send).not.toHaveBeenCalled();
        expect(state.readBody).not.toHaveBeenCalled();
    });

    it('reports a failed transfer only when the retained state is intact', async () => {
        for (const missing of [false, true]) {
            const state = fixture();
            const network = new Error('Network unavailable.');
            const local = new Error('Required record missing.');
            const send = vi.fn(() => Promise.reject(network));
            const inspect = () =>
                missing && send.mock.calls.length > 0
                    ? Promise.reject(local)
                    : Promise.resolve();
            await expect(deliver(state, inspect, send)).rejects.toBe(
                missing ? local : network,
            );
            expect(send).toHaveBeenCalledTimes(1);
            expect(state.readBody).toHaveBeenCalledTimes(1);
            expect(state.copies[0]).toEqual(Uint8Array.of(0));
        }
    });

    it('clears a read copy after a failed transfer before inspecting', async () => {
        const state = fixture();
        const observed: number[][] = [];
        await expect(
            deliver(
                state,
                () => {
                    observed.push(state.copies.flatMap((bytes) => [...bytes]));
                    return Promise.resolve();
                },
                (kind) =>
                    kind === 'body'
                        ? Promise.reject(new Error('Delivery interrupted.'))
                        : Promise.resolve(),
            ),
        ).rejects.toThrow('Delivery interrupted.');
        expect(observed).toEqual([[], [0]]);
    });
});
