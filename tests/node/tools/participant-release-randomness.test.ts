import { describe, expect, it } from 'vitest';

import type { ParticipantKernel } from '#tools/ci/participant-runtime/kernel.js';
import { journalRandomness } from '#tools/ci/participant-runtime/release.js';

// A module memory whose entropy queue serves a fixed journal once, in order.
const journalKernel = (journal: Uint8Array) => {
    const memory = new WebAssembly.Memory({ initial: 2 });
    const outputPointer = 65_536;
    const calls: [number, number][] = [];
    let consumed = 0;
    const kernel = {
        memory,
        release_entropy_output_pointer: () => outputPointer,
        release_entropy_command: (operation: number, length: number) => {
            calls.push([operation, length]);
            if (operation !== 2 || length > journal.length - consumed) return 1;
            new Uint8Array(memory.buffer, outputPointer, length).set(
                journal.subarray(consumed, consumed + length),
            );
            consumed += length;
            return 0;
        },
    } as unknown as ParticipantKernel;
    return { kernel, memory, calls, outputPointer };
};

describe('release journal randomness', () => {
    it('answers proof randomness with the journal bytes in order and clears each output', () => {
        const journal = Uint8Array.from(
            { length: 100 },
            (_unused, index) => index + 1,
        );
        const { kernel, memory, calls, outputPointer } = journalKernel(journal);
        const random = journalRandomness(kernel);
        const first = new Uint8Array(memory.buffer, 0, 30);
        const second = new Uint8Array(memory.buffer, 1000, 70);
        random('proof', first);
        random('proof', second);
        expect([...first]).toEqual([...journal.subarray(0, 30)]);
        expect([...second]).toEqual([...journal.subarray(30)]);
        expect(calls).toEqual([
            [2, 30],
            [2, 70],
        ]);
        expect(
            new Uint8Array(memory.buffer, outputPointer, 70).every(
                (value) => value === 0,
            ),
        ).toBe(true);
    });

    it('refuses other randomness and an exhausted journal without writing', () => {
        const { kernel, memory, calls } = journalKernel(
            new Uint8Array(10).fill(9),
        );
        const random = journalRandomness(kernel);
        const target = new Uint8Array(memory.buffer, 0, 11);
        for (const source of ['enrollment', 'witness', 'ballot'] as const)
            expect(() => random(source, target)).toThrow(
                'Unexpected participant randomness request.',
            );
        expect(calls).toEqual([]);
        expect(() => random('proof', target)).toThrow(
            'The release journal refused a randomness request.',
        );
        expect(target.every((value) => value === 0)).toBe(true);
    });
});
