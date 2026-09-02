import { describe, expect, it } from 'vitest';

import {
    maximumFoundationCopiedBufferByteLength,
    maximumFoundationWasmMemoryByteLength,
} from '../../src/foundation-contract.js';
import { instantiateConstructionKernelCommandRuntime } from '../../src/foundation-kernel/kernel-runtime.js';
import {
    drawPaddedTallyIndependentBytes,
    drawPaddedTallyLabelEntropy,
    openPaddedTallyRuntime,
} from '../../src/padded-tally-runtime.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

const labelByteLength = 40;
const labelPairEntropyByteLength = 2 * labelByteLength + 1;
const maximumWebCryptoRequestByteLength = 65_536;

const expectedLayouts = [
    [2_153, 2_098, 250, 15, 21_192_471, 8_148_114, 45],
    [2_515, 2_290, 364, 19, 23_236_107, 8_936_730, 49],
    [2_837, 2_458, 462, 23, 25_028_143, 9_628_794, 53],
    [3_113, 2_602, 546, 27, 26_564_643, 10_222_362, 56],
    [3_343, 2_722, 616, 31, 27_845_607, 10_717_434, 59],
    [3_527, 2_818, 672, 35, 28_871_035, 11_114_010, 61],
    [3_665, 2_890, 714, 39, 29_640_927, 11_412_090, 63],
    [3_757, 2_938, 742, 43, 30_155_283, 11_611_674, 64],
    [3_803, 2_962, 756, 47, 30_414_103, 11_712_762, 65],
    [3_803, 2_962, 756, 51, 30_417_387, 11_715_354, 65],
] as const;

describe('full padded tally scalar WASM runtime', () => {
    it('compiles the exact complete tally for every admitted topCount', async () => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            { allowUnpinnedKernel: true },
        );
        const runtime = openPaddedTallyRuntime(kernel);

        for (let topCount = 1; topCount <= 10; topCount += 1) {
            const plan = runtime.compilePlan(topCount);
            const expected = expectedLayouts[topCount - 1];
            expect(expected).toBeDefined();
            expect([
                plan.linearCount,
                plan.conjunctionCount,
                plan.negationCount,
                plan.outputCount,
                plan.logicalPayloadByteLength,
                plan.labelEntropyByteLength,
                plan.chunks.length,
            ]).toEqual(expected);
            expect(plan.participantCount).toBe(10);
            expect(plan.optionCount).toBe(10);
            expect(plan.inputWireCount).toBe(410);
            expect(plan.constantCount).toBe(2);
            expect(plan.outputCount).toBe(10 + 1 + 4 * topCount);
            expect(plan.maximumLiveWireCount).toBe(417);
            expect(
                plan.chunks[plan.chunks.length - 1]?.liveWireCountAfterChunk,
            ).toBe(0);
            expect(
                plan.chunks.reduce(
                    (total, chunk) => total + chunk.labelEntropyByteLength,
                    0,
                ),
            ).toBe(plan.labelEntropyByteLength);
            expect(
                plan.chunks.every(
                    (chunk) =>
                        chunk.chunkByteLength > 0 &&
                        chunk.chunkByteLength <= 480_000 &&
                        chunk.labelEntropyByteLength %
                            labelPairEntropyByteLength ===
                            0,
                ),
            ).toBe(true);
        }

        const resources = kernel.measureResources();
        expect(resources.maximumRequestByteLength).toBeLessThan(
            maximumFoundationCopiedBufferByteLength,
        );
        expect(resources.maximumResponseByteLength).toBeLessThan(
            maximumFoundationCopiedBufferByteLength,
        );
        expect(resources.wasmMemoryByteLength).toBeLessThanOrEqual(
            maximumFoundationWasmMemoryByteLength,
        );
    });

    it('draws independent entropy without a seeded label corpus', () => {
        const requestLengths: number[] = [];
        let nextByte = 0;
        const bytes = drawPaddedTallyIndependentBytes(
            maximumWebCryptoRequestByteLength + 17,
            (request) => {
                requestLengths.push(request.byteLength);
                request.fill(nextByte);
                nextByte += 1;
            },
        );
        expect(requestLengths).toEqual([maximumWebCryptoRequestByteLength, 17]);
        expect(bytes[0]).toBe(0);
        expect(bytes[maximumWebCryptoRequestByteLength]).toBe(1);

        let fillCount = 0;
        const pair = drawPaddedTallyLabelEntropy(
            labelPairEntropyByteLength,
            (request) => {
                request.fill(fillCount === 0 ? 0 : 1);
                fillCount += 1;
            },
        );
        expect(fillCount).toBe(2);
        expect(pair.subarray(0, labelByteLength)).toEqual(
            new Uint8Array(labelByteLength),
        );
        expect(pair.subarray(labelByteLength, 2 * labelByteLength)).toEqual(
            new Uint8Array(labelByteLength).fill(1),
        );
        expect(pair[2 * labelByteLength]).toBe(0);
    });
});
