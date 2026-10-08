import { describe, expect, it } from 'vitest';

import {
    operationSeedBytes,
    seededRandomness,
} from '#packages/sdk/src/participant/worker/module/participant-module.js';
import type { ParticipantModule } from '#packages/sdk/src/participant/worker/module/participant-module.js';

// A module memory whose randomness state accepts one seed and reports the
// bytes each of its two streams served.
const seededModule = (refuseSeed = false) => {
    const memory = new WebAssembly.Memory({ initial: 1 });
    const inputPointer = 1024;
    const calls: [number, number][] = [];
    const installed: number[][] = [];
    const drawn = [0, 0];
    const module = {
        memory,
        operation_random_input_pointer: () => inputPointer,
        operation_random_drawn: (stream: number) => drawn[stream],
        operation_random_command: (operation: number, length: number) => {
            calls.push([operation, length]);
            if (operation === 0 || operation === 4 || operation === 5) {
                if (refuseSeed) return 1;
                installed.push([
                    ...new Uint8Array(memory.buffer, inputPointer, length),
                ]);
                return 0;
            }
            return operation === 3 && length === 0 ? 0 : 1;
        },
    } as unknown as ParticipantModule;
    return { module, calls, installed, drawn };
};

const seed = Uint8Array.from(
    { length: Number(operationSeedBytes) },
    (_unused, index) => index + 1,
);

describe('seeded operation randomness', () => {
    it('installs each purpose under its own command and discards its seed', () => {
        for (const [purpose, command] of [
            ['contribution', 0],
            ['ballot', 4],
            ['release', 5],
        ] as const) {
            const { module, calls, installed } = seededModule();
            const randomness = seededRandomness(module, purpose, seed);
            expect(installed).toEqual([[...seed]]);
            randomness.discard();
            expect(calls).toEqual([
                [command, Number(operationSeedBytes)],
                [3, 0],
            ]);
        }
    });

    it('reports the bytes both streams served and those of the proof stream', () => {
        const { module, drawn } = seededModule();
        const randomness = seededRandomness(module, 'ballot', seed);
        expect([randomness.drawn(), randomness.proofDrawn()]).toEqual([0, 0]);
        drawn[0] = 53;
        drawn[1] = 31;
        expect([randomness.drawn(), randomness.proofDrawn()]).toEqual([84, 31]);
    });

    it('refuses a missing, short or refused seed', () => {
        for (const length of [0, Number(operationSeedBytes) - 1])
            expect(() =>
                seededRandomness(
                    seededModule().module,
                    'ballot',
                    seed.subarray(0, length),
                ),
            ).toThrow('No ballot randomness seed is retained.');
        expect(() =>
            seededRandomness(seededModule(true).module, 'contribution', seed),
        ).toThrow('The contribution randomness refused its seed.');
    });
});
