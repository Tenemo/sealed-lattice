import { describe, expect, it } from 'vitest';

import { compileIndependentPaddedTallyModel } from '#tests/padded-tally-transcript-model.js';

const expectedCompletionProfileCensus = [
    [1, 2_153, 2_098, 250, 15, 21_192_471, 8_148_114, 45],
    [2, 2_515, 2_290, 364, 19, 23_236_107, 8_936_730, 49],
    [3, 2_837, 2_458, 462, 23, 25_028_143, 9_628_794, 53],
    [4, 3_113, 2_602, 546, 27, 26_564_643, 10_222_362, 56],
    [5, 3_343, 2_722, 616, 31, 27_845_607, 10_717_434, 59],
    [6, 3_527, 2_818, 672, 35, 28_871_035, 11_114_010, 61],
    [7, 3_665, 2_890, 714, 39, 29_640_927, 11_412_090, 63],
    [8, 3_757, 2_938, 742, 43, 30_155_283, 11_611_674, 64],
    [9, 3_803, 2_962, 756, 47, 30_414_103, 11_712_762, 65],
    [10, 3_803, 2_962, 756, 51, 30_417_387, 11_715_354, 65],
] as const;

describe('independent padded-tally transcript model', () => {
    it('regenerates every admitted completion-profile circuit and chunk census', () => {
        for (const [
            topCount,
            linearCount,
            conjunctionCount,
            negationCount,
            outputCount,
            logicalPayloadByteLength,
            labelEntropyByteLength,
            chunkCount,
        ] of expectedCompletionProfileCensus) {
            const model = compileIndependentPaddedTallyModel(topCount);
            expect({
                topCount: model.topCount,
                inputWireCount: model.inputWireCount,
                constantCount: model.constantCount,
                linearCount: model.linearCount,
                conjunctionCount: model.conjunctionCount,
                negationCount: model.negationCount,
                outputCount: model.outputWires.length,
                operationCount: model.operations.length,
                logicalPayloadByteLength: model.logicalPayloadByteLength,
                labelEntropyByteLength: model.labelEntropyByteLength,
                chunkCount: model.descriptors.length,
            }).toEqual({
                topCount,
                inputWireCount: 410,
                constantCount: 2,
                linearCount,
                conjunctionCount,
                negationCount,
                outputCount,
                operationCount:
                    2 + linearCount + conjunctionCount + negationCount,
                logicalPayloadByteLength,
                labelEntropyByteLength,
                chunkCount,
            });

            let expectedOperationStart = 0;
            let accumulatedChunkByteLength = 0;
            let accumulatedEntropyByteLength = 0;
            for (const [
                descriptorOrdinal,
                descriptor,
            ] of model.descriptors.entries()) {
                expect(descriptor.firstOperation).toBe(expectedOperationStart);
                expect(
                    descriptor.operationEnd > descriptor.firstOperation ||
                        (descriptor.includesTerminal &&
                            descriptor.operationEnd ===
                                descriptor.firstOperation &&
                            descriptor.operationEnd ===
                                model.operations.length),
                ).toBe(true);
                expect(descriptor.includesInitial).toBe(
                    descriptorOrdinal === 0,
                );
                expect(descriptor.includesTerminal).toBe(
                    descriptorOrdinal + 1 === model.descriptors.length,
                );
                expect(descriptor.chunkByteLength).toBeLessThanOrEqual(480_000);
                expectedOperationStart = descriptor.operationEnd;
                accumulatedChunkByteLength += descriptor.chunkByteLength - 250;
                accumulatedEntropyByteLength +=
                    descriptor.labelEntropyByteLength;
            }
            expect(expectedOperationStart).toBe(model.operations.length);
            expect(accumulatedChunkByteLength).toBe(
                model.logicalPayloadByteLength,
            );
            expect(accumulatedEntropyByteLength).toBe(
                model.labelEntropyByteLength,
            );
        }
    });

    it.each([0, 11, 1.5, Number.NaN])(
        'rejects a non-profile topCount of %s',
        (topCount) => {
            expect(() =>
                compileIndependentPaddedTallyModel(topCount),
            ).toThrowError(RangeError);
        },
    );
});
