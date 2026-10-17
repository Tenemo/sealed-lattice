import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { runInNewContext } from 'node:vm';

import { describe, expect, it } from 'vitest';

import {
    proofCompletionHaltingClient,
    preparationHaltingClient,
    validateProofCompletionObservation,
} from '#tools/ci/participant-proof-completion.js';
import type {
    ProofCompletionHaltObservation,
    ProofCompletionSlotObservation,
    PreparationCut,
} from '#tools/ci/participant-proof-completion.js';

const source =
    Buffer.from(`globalThis.run = async (store, commitContribution) => {
    const proof = [], state = { publicRecords: [] }, contributionPhase = { body: 7 }, session = {}, context = {}, offerSigningOperation = {bodyHeader: 0};
    let header = new Uint8Array();
    const signing = () => header, concatenate = () => header, unsigned16 = () => header, unsigned64 = () => header;
    let stored = 0, used = 4;
    const buffer = Uint8Array.of(1, 2, 3, 4);
    const appendSlot = async () => {
        await store({ offset: stored, length: used }, buffer.subarray(0, used));
        proof.push({ offset: stored, length: used });
        stored += used;
    };
    await appendSlot();
    used = 3;
    const writer = { finish: async () => { await appendSlot(); return 7; } };
    const length = await writer.finish();
    header = signing(context, offerSigningOperation.bodyHeader, concatenate(unsigned16(state.position), unsigned64(BigInt(length))));
    await commitContribution(session, { state: { ...state, phase: contributionPhase.body, header, publicRecords: [...state.publicRecords, ...proof], privateRecords: [], seed: new Uint8Array() }, staged: true, clearCheckpoint: true });
    return length;
};`);

describe('instrumented participant proof completion boundaries', () => {
    it('finds every preparation and proof completion interruption boundary in the built participant worker', async () => {
        const worker = await readFile(
            path.resolve('packages/sdk/dist/participant-worker.js'),
        );
        for (const kind of [
            'contribution',
            'selection',
            'selection-readback',
            'endorsement',
        ] as const)
            for (const phase of kind === 'contribution'
                ? [4, 5, 6, 7, 8, 9]
                : kind === 'selection-readback'
                  ? [1]
                  : [1, 2])
                expect(() =>
                    preparationHaltingClient(worker, { kind, phase }),
                ).not.toThrow();
        for (const cut of ['final-record', 'body-commit'] as const)
            expect(() =>
                proofCompletionHaltingClient(worker, cut),
            ).not.toThrow();
    });
    it('halts after authenticated selection readback and before any endorsement work', async () => {
        const worker = Buffer.from(`globalThis.select = async () => {
            const publication = { addBytes: async () => undefined, finish: globalThis.readback };
            const session = {}, relay = {}, retained = {};
            await publication.addBytes('signature.bin', retained.signature);
            await publication.finish();
            await endorseSetup(session, relay, retained);
        };`);
        const client = preparationHaltingClient(worker, {
            kind: 'selection-readback',
            phase: 1,
        });
        let release!: () => void;
        const readback = new Promise<void>((resolve) => {
            release = resolve;
        });
        let observed!: (message: unknown) => void;
        const reached = new Promise((resolve) => {
            observed = resolve;
        });
        let endorsements = 0;
        const context = {
            readback: () => readback,
            endorseSetup: () => {
                endorsements++;
            },
            self: { postMessage: observed },
            select: undefined as (() => Promise<void>) | undefined,
        };
        runInNewContext(client.worker.toString('utf8'), context);
        const running = context.select!();
        await Promise.resolve();
        expect(endorsements).toBe(0);
        release();
        expect(
            await Promise.race([reached, running.then(() => 'completed')]),
        ).toEqual({
            type: 'participant-preparation-halt',
            kind: 'selection-readback',
            phase: 1,
        });
        expect(endorsements).toBe(0);
        const rejected = {
            ...context,
            readback: () => Promise.reject(new Error('Readback refused.')),
            select: undefined as (() => Promise<void>) | undefined,
        };
        runInNewContext(client.worker.toString('utf8'), rejected);
        await expect(rejected.select!()).rejects.toThrow('Readback refused.');
        expect(endorsements).toBe(0);
    });
    it('halts on independent preparation intents after readback while the root generation stays four', async () => {
        const rootSource =
            Buffer.from(`globalThis.commit = async (head, manifest) => {
            await globalThis.readback();
            const reopened = new Uint8Array();
            return { head, plaintext: reopened, manifest };
        };`);
        const journal = (field: number, phase: number) => {
            const fields = [Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0)];
            fields[field] = Buffer.from([phase]);
            return Buffer.concat([
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
            [1, 'selection', 2],
            [2, 'endorsement', 1],
            [2, 'endorsement', 2],
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
    it.each([
        source,
        Buffer.from(
            'const documentation = ' +
                JSON.stringify(source.toString('utf8')) +
                ';\n' +
                source.toString('utf8'),
        ),
    ])(
        'observes awaited writes and halts before committing completed authority',
        async (workerSource) => {
            for (const cut of ['final-record', 'body-commit'] as const) {
                const client = proofCompletionHaltingClient(workerSource, cut);
                const slots: ProofCompletionSlotObservation[] = [];
                let accept!: (value: ProofCompletionHaltObservation) => void;
                const reached = new Promise<ProofCompletionHaltObservation>(
                    (resolve) => {
                        accept = resolve;
                    },
                );
                let completedWrites = 0;
                let release!: () => void;
                const firstWrite = new Promise<void>((resolve) => {
                    release = resolve;
                });
                const context = {
                    crypto: webcrypto,
                    performance,
                    self: {
                        postMessage: (
                            value:
                                | ProofCompletionSlotObservation
                                | ProofCompletionHaltObservation,
                        ) => {
                            if (value.type === 'participant-proof-record') {
                                assert.equal(completedWrites, slots.length + 1);
                                slots.push(value);
                            } else accept(value);
                        },
                    },
                    run: undefined as
                        | undefined
                        | ((
                              store: () => Promise<void>,
                              commit: () => void,
                          ) => Promise<number>),
                };
                runInNewContext(client.worker.toString('utf8'), context);
                const running = context.run!(
                    async () => {
                        await firstWrite;
                        completedWrites++;
                    },
                    () => {
                        throw new Error(
                            'Completed body committed before interruption',
                        );
                    },
                );
                await Promise.resolve();
                expect(slots).toEqual([]);
                release();
                const halt = await Promise.race([
                    reached,
                    running.then(() => {
                        throw new Error('Did not halt');
                    }),
                ]);
                expect(halt.cut).toBe(cut);
                expect(halt.proofBytes).toBe(7);
                validateProofCompletionObservation(
                    { slots, halt },
                    { minimumProofBytes: 1, maximumProofBytes: 8 },
                    4,
                );
                expect(slots.map((slot) => slot.sha512)).toEqual(
                    [4, 3].map((length) =>
                        createHash('sha512')
                            .update(
                                Uint8Array.of(1, 2, 3, 4).subarray(0, length),
                            )
                            .digest('hex'),
                    ),
                );
                expect(client.originalDigest).toBe(
                    createHash('sha512').update(workerSource).digest('hex'),
                );
                expect(client.digest).not.toBe(client.originalDigest);
            }
        },
    );
    it('refuses ambiguous boundaries and malformed replay inventories', () => {
        for (const input of [Buffer.from(''), Buffer.concat([source, source])])
            expect(() =>
                proofCompletionHaltingClient(input, 'final-record'),
            ).toThrow('one completed');
        const slot: ProofCompletionSlotObservation = {
            type: 'participant-proof-record',
            offset: 0,
            length: 3,
            sha512: 'a'.repeat(128),
            instrumentationMilliseconds: 0,
        };
        const halt: ProofCompletionHaltObservation = {
            type: 'participant-proof-completion',
            cut: 'final-record',
            proofBytes: 3,
            storedSlots: 1,
        };
        validateProofCompletionObservation(
            { slots: [slot], halt },
            { minimumProofBytes: 1, maximumProofBytes: 8 },
            4,
        );
        for (const slots of [
            [],
            [slot, slot],
            [{ ...slot, length: 4 }],
            [{ ...slot, offset: 1 }],
        ])
            expect(() =>
                validateProofCompletionObservation(
                    { slots, halt },
                    { minimumProofBytes: 1, maximumProofBytes: 8 },
                    4,
                ),
            ).toThrow();
    });
});
