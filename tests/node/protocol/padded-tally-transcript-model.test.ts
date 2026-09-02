import { describe, expect, it } from 'vitest';

import {
    compileIndependentPaddedTallyModel,
    projectIndependentPaddedTallyWidth,
    screenIndependentPaddedTallyPadKmac,
} from '#tests/padded-tally-transcript-model.js';

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
            expect(model.kmacCensus.generationCallCount).toBe(
                model.kmacCensus.labelOutputCount +
                    model.kmacCensus.continuationOutputCount,
            );
            expect(model.kmacCensus.hiddenReplacementCount).toBe(
                model.kmacCensus.generationCallCount / 2,
            );
        }
    });

    it('independently regenerates the maximum-width KMAC assumption census', () => {
        expect(compileIndependentPaddedTallyModel(10).kmacCensus).toEqual({
            labelKeyCount: 2_892_680,
            continuationKeyCount: 59_240,
            keyCount: 2_951_920,
            labelOutputCount: 11_896_480,
            continuationOutputCount: 59_240,
            generationCallCount: 11_955_720,
            selectedEvaluationCallCount: 3_596_140,
            unavailableLabelReplacementCount: 5_948_240,
            counterfactualContinuationReplacementCount: 29_620,
            hiddenReplacementCount: 5_977_860,
            maximumLabelFanOut: 332,
            labelFanOutDistribution: [
                [0, 14_240],
                [2, 2_062_560],
                [4, 236_760],
                [6, 240],
                [8, 119_680],
                [10, 370_400],
                [12, 2_000],
                [14, 50_400],
                [26, 24_000],
                [28, 8_000],
                [70, 80],
                [88, 3_440],
                [124, 80],
                [332, 800],
            ],
        });
    });

    it('projects the theorem-covered label width before materialization', () => {
        const model = compileIndependentPaddedTallyModel(10);
        const admittedProjection = projectIndependentPaddedTallyWidth(
            model,
            40,
        );
        expect(admittedProjection.logicalPayloadByteLength).toBe(
            model.logicalPayloadByteLength,
        );
        expect(admittedProjection.participantLabelEntropyByteLength).toBe(
            model.labelEntropyByteLength,
        );
        expect(admittedProjection.chunkByteLengths).toEqual(
            model.descriptors.map((descriptor) => descriptor.chunkByteLength),
        );
        expect(admittedProjection.maximumLiveWireCount).toBe(
            model.maximumLiveWireCount,
        );
        expect(admittedProjection.liveWireCountsAfterChunks).toEqual(
            model.liveWireCountsAfterChunks,
        );

        const theoremProjection = projectIndependentPaddedTallyWidth(
            model,
            192,
        );
        expect(theoremProjection).toMatchObject({
            labelByteLength: 192,
            tokenByteLength: 193,
            initialWirePayloadByteLength: 772,
            constantPayloadByteLength: 772,
            linearPayloadByteLength: 3_088,
            conjunctionPayloadByteLength: 44_502,
            terminalPayloadByteLength: 3_861,
            labelPairEntropyByteLength: 385,
            logicalPayloadByteLength: 144_073_563,
            participantChunkCorpusByteLength: 144_152_063,
            completeChunkCorpusByteLength: 1_441_520_630,
            participantLabelEntropyByteLength: 55_684_090,
            completeLabelEntropyByteLength: 556_840_900,
            manifestByteLength: 24_668,
            chunkCount: 314,
            maximumChunkByteLength: 479_238,
            maximumChunkLabelEntropyByteLength: 693_385,
            maximumLiveWireCount: 415,
            maximumGenerationCheckpointByteLength: 1_263_064,
            maximumEvaluationCheckpointByteLength: 3_399_972,
            maximumChunkGenerationRequestByteLength: 1_445_984,
            maximumChunkEvaluationRequestByteLength: 8_184_709,
            maximumChunkGenerationResponseByteLength: 1_742_379,
            maximumChunkEvaluationResponseByteLength: 3_399_981,
        });
        expect(theoremProjection.chunkByteLengths.slice(0, 3)).toEqual([
            470_348, 476_150, 473_062,
        ]);
        expect(theoremProjection.chunkByteLengths.slice(-3)).toEqual([
            479_238, 436_554, 301_605,
        ]);
        expect(theoremProjection.completeChunkCorpusByteLength).toBeLessThan(
            2_147_483_648,
        );
        expect(
            theoremProjection.maximumChunkLabelEntropyByteLength,
        ).toBeLessThan(8_388_608);
        expect(
            theoremProjection.maximumChunkEvaluationRequestByteLength,
        ).toBeLessThan(8_388_608);
        expect(
            theoremProjection.maximumChunkGenerationResponseByteLength,
        ).toBeLessThan(8_388_608);
        expect(
            theoremProjection.maximumChunkEvaluationResponseByteLength,
        ).toBeLessThan(8_388_608);
    });

    it('keeps every admitted output width under the hard corpus screen', () => {
        for (let topCount = 1; topCount <= 10; topCount += 1) {
            const projection = projectIndependentPaddedTallyWidth(
                compileIndependentPaddedTallyModel(topCount),
                192,
            );
            expect(projection.completeChunkCorpusByteLength).toBeLessThan(
                2_147_483_648,
            );
            expect(projection.maximumChunkByteLength).toBeLessThanOrEqual(
                480_000,
            );
            expect(projection.maximumChunkLabelEntropyByteLength).toBeLessThan(
                8_388_608,
            );
            expect(
                projection.maximumChunkEvaluationRequestByteLength,
            ).toBeLessThan(8_388_608);
        }
    });

    it('evaluates the exact long-key KMAC ideal-permutation theorem operands', () => {
        const model = compileIndependentPaddedTallyModel(10);
        expect(() =>
            screenIndependentPaddedTallyPadKmac(model, 40, 80),
        ).toThrow(
            'The KMAC key does not satisfy the outer-keyed-sponge theorem.',
        );

        const screen = screenIndependentPaddedTallyPadKmac(model, 192, 80);
        expect(screen).toMatchObject({
            rateBitLength: 1_088,
            capacityBitLength: 512,
            keyBitLength: 1_536,
            keyPrefixBitOffsetModuloRate: 40,
            derivedKeySecurityBitLength: 488,
            paddedKeyPrefixBlockCount: 3,
            constructionEffectiveBlockBudget: 2 ** 80,
            quantumPrimitiveQueryBudget: 2 ** 80,
            challengedKeyCount: 2_951_920,
        });
        expect(screen.singleKeySecurityBitLength).toBeCloseTo(133.228, 3);
        expect(screen.completeHybridSecurityBitLength).toBeCloseTo(111.735, 3);
        expect(screen.completeHybridSecurityBitLength - 30).toBeGreaterThan(80);
        expect(
            screenIndependentPaddedTallyPadKmac(model, 184, 80)
                .completeHybridSecurityBitLength - 30,
        ).toBeLessThan(80);
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
