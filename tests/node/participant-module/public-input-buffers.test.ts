import { describe, expect, it } from 'vitest';

import { writeBufferInput } from '#packages/sdk/src/participant/worker/module/participant-module.js';
import { inputBuffers } from '#tests/node/participant-module/public-input-commands.js';
import { instantiate } from '#tests/node/participant-module/public-input-fixture.js';

describe('participant module public input', () => {
    it('writes each input buffer up to the capacity the module reports, in memory no other buffer holds', async () => {
        const { module } = await instantiate();
        const extents = Object.entries(inputBuffers).map(([name, buffer]) => ({
            name,
            start: buffer.pointer(module) >>> 0,
            capacity: buffer.capacity(module),
        }));
        // The buffers of the certificate collector, close verifier, ballot
        // classifier and evaluation each hold a mebibyte.
        for (const name of [
            'completion',
            'close',
            'ballotBody',
            'evaluationTarget',
        ])
            expect(
                extents.find((extent) => extent.name === name)?.capacity,
                name,
            ).toBe(1 << 20);
        const sorted = [...extents].sort(
            (left, right) => left.start - right.start,
        );
        for (const [index, extent] of sorted.entries()) {
            expect(extent.capacity, extent.name).toBeGreaterThan(0);
            expect(
                extent.start + extent.capacity,
                extent.name,
            ).toBeLessThanOrEqual(
                index + 1 < sorted.length
                    ? sorted[index + 1].start
                    : module.memory.buffer.byteLength,
            );
        }
        for (const buffer of [
            'completion',
            'close',
            'ballotBody',
            'evaluationTarget',
        ] as const) {
            const capacity = inputBuffers[buffer].capacity(module);
            writeBufferInput(module, buffer, new Uint8Array(capacity));
            expect(() =>
                writeBufferInput(module, buffer, new Uint8Array(capacity + 1)),
            ).toThrow('Module input exceeds its buffer.');
        }
    });
});
