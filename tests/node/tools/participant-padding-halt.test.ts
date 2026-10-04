import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { runInNewContext } from 'node:vm';

import { describe, expect, it } from 'vitest';

import {
    paddingHaltingClient,
    preparationHaltingClient,
    validatePaddingObservation,
} from '#tools/ci/participant-padding-halt.js';
import type {
    PaddingHaltObservation,
    PaddingSlotObservation,
    PreparationCut,
} from '#tools/ci/participant-padding-halt.js';

const source =
    Buffer.from(`globalThis.append = async (store, buffer, slot, next, slots, length) => {
    await store(slot, buffer.subarray(0, slot.length));
    return 'finished';
};`);

describe('instrumented participant padding boundaries', () => {
    it('halts on independent preparation intents after readback while the root generation stays four', async () => {
        const rootSource =
            Buffer.from(`globalThis.commit = async (head, manifest) => {
            await globalThis.readback();
            const reopened = new Uint8Array();
            return { head, plaintext: reopened, manifest };
        };`);
        const journal = (field: number, phase: number) => {
            const fields = [Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0)];
            fields[field] =
                field === 0
                    ? Buffer.from([80, 67, 83, 52, phase])
                    : Buffer.from([phase]);
            return Buffer.concat([
                Buffer.from('PRE1'),
                ...fields.flatMap((bytes) => {
                    const length = Buffer.alloc(4);
                    length.writeUInt32LE(bytes.length);
                    return [length, bytes];
                }),
            ]);
        };
        for (const [field, kind, phase] of [
            [0, 'contribution', 5],
            [0, 'contribution', 8],
            [1, 'selection', 1],
            [2, 'endorsement', 1],
        ] as const) {
            const cut: PreparationCut = { kind, phase };
            const client = preparationHaltingClient(rootSource, cut);
            const messages: unknown[] = [];
            let readback = () => Promise.resolve();
            let accept!: (value: unknown) => void;
            const message = new Promise((resolve) => {
                accept = resolve;
            });
            const context = {
                readback: () => readback(),
                self: {
                    postMessage: (value: unknown) => {
                        messages.push(value);
                        accept(value);
                    },
                },
                commit: undefined as
                    | undefined
                    | ((
                          head: { generation: number },
                          manifest: { suffixes: { preparation: Uint8Array } },
                      ) => Promise<unknown>),
            };
            runInNewContext(client.worker.toString('utf8'), context);
            const untouched = await context.commit!(
                { generation: 4 },
                {
                    suffixes: {
                        preparation: journal(field, phase === 1 ? 2 : 4),
                    },
                },
            );
            expect(untouched).toHaveProperty('head.generation', 4);
            readback = () => Promise.reject(new Error('Readback refused.'));
            await expect(
                context.commit!(
                    { generation: 4 },
                    { suffixes: { preparation: journal(field, phase) } },
                ),
            ).rejects.toThrow('Readback refused.');
            expect(messages).toEqual([]);
            let finishReadback!: () => void;
            const pendingReadback = new Promise<void>((resolve) => {
                finishReadback = resolve;
            });
            readback = () => pendingReadback;
            const stopped = context.commit!(
                { generation: 4 },
                { suffixes: { preparation: journal(field, phase) } },
            );
            await Promise.resolve();
            expect(messages).toEqual([]);
            finishReadback();
            const observed = await Promise.race([
                message,
                stopped.then(() => {
                    throw new Error('The phase completed instead of halting.');
                }),
            ]);
            expect(observed).toEqual({
                type: 'participant-preparation-halt',
                kind,
                phase,
            });
        }
    });
    it('halts only after the awaited store and identifies partial padding and the final slot', async () => {
        for (const cut of ['padding', 'final-slot'] as const) {
            const client = paddingHaltingClient(source, cut);
            const observed: PaddingSlotObservation[] = [];
            let resolve!: (halt: PaddingHaltObservation) => void;
            const reached = new Promise<PaddingHaltObservation>((accept) => {
                resolve = accept;
            });
            let stored = 0;
            const context = {
                crypto: webcrypto,
                performance,
                self: {
                    postMessage: (
                        message:
                            PaddingSlotObservation | PaddingHaltObservation,
                    ) => {
                        if (message.type === 'participant-padding-slot') {
                            assert.equal(stored, observed.length + 1);
                            observed.push(message);
                        } else resolve(message);
                    },
                },
                append: undefined as
                    | undefined
                    | ((
                          store: () => Promise<void>,
                          bytes: Uint8Array,
                          slot: { offset: number; length: number },
                          next: number,
                          slots: readonly { offset: number; length: number }[],
                          length: number,
                      ) => Promise<string>),
            };
            runInNewContext(client.worker.toString('utf8'), context);
            const slots = [
                { offset: 0, length: 4 },
                { offset: 4, length: 4 },
            ];
            const buffers = [new Uint8Array([1, 2, 3, 0]), new Uint8Array(4)];
            for (const [index, slot] of slots.entries()) {
                const running = context.append!(
                    () => {
                        stored++;
                        return Promise.resolve();
                    },
                    buffers[index],
                    slot,
                    index,
                    slots,
                    3,
                );
                if (cut === 'final-slot' && index === 0)
                    assert.equal(await running, 'finished');
                else {
                    const halt = await Promise.race([
                        reached,
                        running.then(() => {
                            throw new Error(
                                'The instrumented operation finished before its cut.',
                            );
                        }),
                    ]);
                    assert.equal(halt.cut, cut);
                    assert.equal(halt.proofBytes, 3);
                    assert.equal(halt.slotOffset, cut === 'padding' ? 0 : 4);
                    assert.equal(halt.storedSlots, cut === 'padding' ? 1 : 2);
                    assert.equal(halt.totalSlots, 2);
                    assert.equal(halt.paddingOnly, cut === 'final-slot');
                    validatePaddingObservation(
                        { slots: observed, halt },
                        { minimumProofBytes: 1, maximumProofBytes: 8 },
                        4,
                    );
                    break;
                }
            }
            for (const [index, slot] of observed.entries())
                expect(slot.sha512).toBe(
                    createHash('sha512').update(buffers[index]).digest('hex'),
                );
            expect(client.originalDigest).toBe(
                createHash('sha512').update(source).digest('hex'),
            );
            expect(client.digest).not.toBe(client.originalDigest);
        }
    });
    it('refuses missing or ambiguous store boundaries and malformed replay observations', () => {
        expect(() => paddingHaltingClient(Buffer.from(''), 'padding')).toThrow(
            'one completed',
        );
        expect(() =>
            paddingHaltingClient(Buffer.concat([source, source]), 'padding'),
        ).toThrow('one completed');
        const slot: PaddingSlotObservation = {
            type: 'participant-padding-slot',
            offset: 0,
            length: 4,
            sha512: 'a'.repeat(128),
            instrumentationMilliseconds: 0,
        };
        const halt: PaddingHaltObservation = {
            type: 'participant-padding-halt',
            cut: 'padding',
            proofBytes: 3,
            slotOffset: 0,
            slotLength: 4,
            storedSlots: 1,
            totalSlots: 2,
            paddingOnly: false,
        };
        expect(() =>
            validatePaddingObservation(
                { slots: [slot], halt: { ...halt, proofBytes: 4 } },
                { minimumProofBytes: 1, maximumProofBytes: 8 },
                4,
            ),
        ).toThrow();
        expect(() =>
            validatePaddingObservation(
                { slots: [{ ...slot, offset: 1 }], halt },
                { minimumProofBytes: 1, maximumProofBytes: 8 },
                4,
            ),
        ).toThrow();
        expect(() =>
            validatePaddingObservation(
                { slots: [slot], halt: { ...halt, cut: 'final-slot' } },
                { minimumProofBytes: 1, maximumProofBytes: 8 },
                4,
            ),
        ).toThrow();
    });
});
