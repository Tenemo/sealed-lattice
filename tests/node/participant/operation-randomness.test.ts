import { describe, expect, it } from 'vitest';

import {
    operationSeedBytes,
    seededRandomness,
} from '#packages/sdk/src/participant/worker/kernel.js';
import type { ParticipantKernel } from '#packages/sdk/src/participant/worker/kernel.js';

// A module memory whose randomness state accepts one seed and answers each
// stream's requests with a counter pattern of that stream, so a test can
// tell which stream served a request.
const seededKernel = (refuseSeed = false, growOnRead = false) => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const inputPointer = 1024;
    const outputPointer = 65_536;
    const calls: [number, number][] = [];
    const installed: number[][] = [];
    const drawn = [0, 0, 0];
    const kernel = {
        memory,
        operation_random_input_pointer: () => inputPointer,
        operation_random_output_pointer: () => outputPointer,
        operation_random_command: (operation: number, length: number) => {
            calls.push([operation, length]);
            if (operation === 0 || operation === 4 || operation === 5) {
                if (refuseSeed) return 1;
                installed.push([
                    ...new Uint8Array(memory.buffer, inputPointer, length),
                ]);
                return 0;
            }
            if (operation === 1 || operation === 2) {
                if (growOnRead) memory.grow(1);
                const output = new Uint8Array(
                    memory.buffer,
                    outputPointer,
                    length,
                );
                for (let index = 0; index < length; index++)
                    output[index] = operation * 100 + drawn[operation]++;
                return 0;
            }
            return operation === 3 && length === 0 ? 0 : 1;
        },
    } as unknown as ParticipantKernel;
    return { kernel, memory, calls, installed, outputPointer };
};

const seed = Uint8Array.from(
    { length: Number(operationSeedBytes) },
    (_unused, index) => index + 1,
);

describe('seeded operation randomness', () => {
    it('fills the original destination and counts bytes when the nested command grows memory', () => {
        const { kernel, memory, outputPointer, calls } = seededKernel(
            false,
            true,
        );
        const randomness = seededRandomness(
            kernel,
            'contribution',
            seed,
            'witness',
        );
        const destinationOffset = 8192;
        for (const [source, length, firstByte] of [
            ['witness', 17, 100],
            ['proof', 31, 200],
            ['witness', 5, 117],
        ] as const) {
            const before = new Uint8Array(
                memory.buffer,
                destinationOffset - 1,
                length + 2,
            );
            before.fill(77);
            const target = new Uint8Array(
                memory.buffer,
                destinationOffset,
                length,
            );
            randomness.random(source, target);
            expect(target.byteLength).toBe(0);
            expect([
                ...new Uint8Array(memory.buffer, destinationOffset, length),
            ]).toEqual(Array.from({ length }, (_, index) => firstByte + index));
            expect(
                new Uint8Array(memory.buffer, destinationOffset - 1, 1)[0],
            ).toBe(77);
            expect(
                new Uint8Array(memory.buffer, destinationOffset + length, 1)[0],
            ).toBe(77);
            expect(
                new Uint8Array(memory.buffer, outputPointer, length).every(
                    (value) => value === 0,
                ),
            ).toBe(true);
        }
        expect(randomness.drawn()).toBe(53);
        expect(randomness.proofDrawn()).toBe(31);
        expect(calls).toEqual([
            [0, 64],
            [1, 17],
            [2, 31],
            [1, 5],
        ]);
    });

    it('installs each purpose under its own command and serves its two streams in order', () => {
        for (const [purpose, command, first] of [
            ['contribution', 0, 'witness'],
            ['ballot', 4, 'ballot'],
        ] as const) {
            const { kernel, memory, calls, installed, outputPointer } =
                seededKernel();
            const randomness = seededRandomness(kernel, purpose, seed, first);
            expect(installed).toEqual([[...seed]]);
            const proof = new Uint8Array(memory.buffer, 0, 3);
            randomness.random('proof', proof);
            const stream = new Uint8Array(memory.buffer, 100, 2);
            randomness.random(first, stream);
            expect([...proof]).toEqual([200, 201, 202]);
            expect([...stream]).toEqual([100, 101]);
            expect(randomness.drawn()).toBe(5);
            // Each copied output is cleared in module memory.
            expect(
                new Uint8Array(memory.buffer, outputPointer, 3).every(
                    (value) => value === 0,
                ),
            ).toBe(true);
            randomness.discard();
            expect(calls).toEqual([
                [command, Number(operationSeedBytes)],
                [2, 3],
                [1, 2],
                [3, 0],
            ]);
        }
    });

    it('serves a release only from its proof stream', () => {
        const { kernel, memory, calls } = seededKernel();
        const randomness = seededRandomness(kernel, 'release', seed);
        const target = new Uint8Array(memory.buffer, 0, 4);
        for (const source of ['enrollment', 'witness', 'ballot'] as const)
            expect(() => randomness.random(source, target)).toThrow(
                'The release randomness refused a request.',
            );
        expect(target.every((value) => value === 0)).toBe(true);
        randomness.random('proof', target);
        expect([...target]).toEqual([200, 201, 202, 203]);
        expect(calls).toEqual([
            [5, Number(operationSeedBytes)],
            [2, 4],
        ]);
    });

    it('refuses a missing, short or refused seed', () => {
        for (const length of [0, Number(operationSeedBytes) - 1])
            expect(() =>
                seededRandomness(
                    seededKernel().kernel,
                    'ballot',
                    seed.subarray(0, length),
                    'ballot',
                ),
            ).toThrow('No ballot randomness seed is retained.');
        expect(() =>
            seededRandomness(
                seededKernel(true).kernel,
                'contribution',
                seed,
                'witness',
            ),
        ).toThrow('The contribution randomness refused its seed.');
    });
});
