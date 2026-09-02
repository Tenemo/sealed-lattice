import { describe, expect, it } from 'vitest';

import {
    addFieldPolynomials,
    compileCompletionPreparationModel,
    completionSubsets,
    enumerateCorruptProjectionCensuses,
    enumerateMatchedMaskHiddenSpan,
    evaluateFieldPolynomial,
    hiddenSourceSubsetCount,
    matchedMaskWordKey,
    multiplyFieldPolynomials,
} from '#tests/complete-preparation-model.js';
import { compileIndependentPaddedTallyModel } from '#tests/padded-tally-transcript-model.js';

const participantCount = 10;

describe('independent complete preparation model', () => {
    it('regenerates the exact contribution, opening, and key census', () => {
        const model = compileCompletionPreparationModel(
            compileIndependentPaddedTallyModel(10),
        );
        expect(model.preparation).toEqual({
            participantCount: 10,
            lowSubsetCount: 120,
            terminalSubsetCount: 45,
            aggregateSubsetKeyCount: 165,
            lowSubsetSlotsPerSender: 84,
            terminalSubsetSlotsPerSender: 36,
            contributionCount: 1_200,
            contributionOpeningByteLength: 80,
            contributionOpeningCorpusByteLength: 96_000,
            commitmentCount: 1_200,
            commitmentCorpusByteLength: 76_800,
            remoteSenderRecipientCount: 90,
            openingsPerRemotePlaintext: 84,
            remoteOpeningOccurrenceCount: 7_560,
            remoteOpeningCorpusByteLength: 604_800,
            directedPairwiseMasterCount: 100,
            remotePairwiseMasterCount: 90,
            selfPairwiseMasterCount: 10,
            pairwiseMasterCorpusByteLength: 3_200,
            preparationPlaintextByteLength: 6_766,
            preparationPlaintextCorpusByteLength: 608_940,
            heldLowSubsetKeyCountPerParticipant: 84,
            heldTerminalSubsetKeyCountPerParticipant: 36,
            heldSubsetKeyCountPerParticipant: 120,
        });
    });

    it('regenerates the complete derived-stream census for every output width', () => {
        for (let topCount = 1; topCount <= 10; topCount += 1) {
            const tally = compileIndependentPaddedTallyModel(topCount);
            const { streams } = compileCompletionPreparationModel(tally);
            expect(streams).toMatchObject({
                topCount,
                conjunctionCount: tally.conjunctionCount,
                outputCount: 11 + 4 * topCount,
                generationChunkCount: tally.descriptors.length,
                uniqueMatchedLowSubkeyCount: 120,
                uniqueMatchedHighZeroSubkeyCount: 120,
                uniqueTerminalZeroSubkeyCount: 45,
                uniqueSourceSubkeyCount: 840,
                uniqueReceiverBSubkeyCount: 840,
                uniquePairwisePadSubkeyCount: 100,
                uniqueDerivedSubkeyCount: 2_065,
                maximumSourceDerivedSubkeyInvocationCount: 6_720,
                chunkInventoryDerivedSubkeyInvocationCount:
                    tally.descriptors.length * 8_120,
                maximumDerivedSubkeyInvocationCount:
                    6_720 + tally.descriptors.length * 8_120,
                distinctSourceAesBlockCount: 1_080,
                scalarSourceAesInvocationCount: 8_640,
            });
            expect(streams.distinctAesBlockCount).toBe(
                streams.distinctMatchedLowAesBlockCount +
                    streams.distinctMatchedHighZeroAesBlockCount +
                    streams.distinctTerminalZeroAesBlockCount +
                    streams.distinctSourceAesBlockCount +
                    streams.distinctReceiverBAesBlockCount +
                    streams.distinctPairwisePadAesBlockCount,
            );
            expect(streams.scalarAesInvocationCount).toBeGreaterThan(
                streams.distinctAesBlockCount,
            );
        }

        expect(
            compileCompletionPreparationModel(
                compileIndependentPaddedTallyModel(10),
            ).streams,
        ).toEqual({
            topCount: 10,
            conjunctionCount: 2_962,
            outputCount: 51,
            generationChunkCount: 65,
            uniqueMatchedLowSubkeyCount: 120,
            uniqueMatchedHighZeroSubkeyCount: 120,
            uniqueTerminalZeroSubkeyCount: 45,
            uniqueSourceSubkeyCount: 840,
            uniqueReceiverBSubkeyCount: 840,
            uniquePairwisePadSubkeyCount: 100,
            uniqueDerivedSubkeyCount: 2_065,
            maximumSourceDerivedSubkeyInvocationCount: 6_720,
            chunkInventoryDerivedSubkeyInvocationCount: 527_800,
            maximumDerivedSubkeyInvocationCount: 534_520,
            distinctMatchedLowAesBlockCount: 2_880,
            distinctMatchedHighZeroAesBlockCount: 33_360,
            distinctTerminalZeroAesBlockCount: 90,
            distinctSourceAesBlockCount: 1_080,
            distinctReceiverBAesBlockCount: 7_464_240,
            distinctPairwisePadAesBlockCount: 3_554_400,
            distinctAesBlockCount: 11_056_050,
            scalarMatchedLowAesInvocationCount: 2_488_080,
            scalarMatchedHighZeroAesInvocationCount: 2_643_480,
            scalarTerminalZeroAesInvocationCount: 18_360,
            scalarSourceAesInvocationCount: 8_640,
            scalarReceiverBAesInvocationCount: 59_713_920,
            scalarPairwisePadAesInvocationCount: 7_108_800,
            scalarAesInvocationCount: 71_981_280,
        });
    });

    it('finds the hidden source direction and corrupt-source extraction boundary', () => {
        for (let corruptCount = 0; corruptCount <= 3; corruptCount += 1) {
            const projections =
                enumerateCorruptProjectionCensuses(corruptCount);
            expect(projections).toHaveLength([1, 10, 45, 120][corruptCount]);
            for (const projection of projections) {
                expect(
                    projection.hiddenHonestSourceBitCount +
                        projection.extractableCorruptSourceBitCount,
                ).toBe(400);
                expect(projection.hiddenDirectedPairwiseMasterCount).toBe(
                    projection.honestSourceCount ** 2,
                );
                for (
                    let sourcePosition = 0;
                    sourcePosition < 10;
                    sourcePosition += 1
                ) {
                    const hiddenSubsetCount = hiddenSourceSubsetCount(
                        projection.corruptParticipants,
                        sourcePosition,
                    );
                    expect(hiddenSubsetCount).toBe(
                        projection.corruptParticipants.includes(sourcePosition)
                            ? 0
                            : [84, 28, 7, 1][corruptCount],
                    );
                }
            }
        }
        expect(
            enumerateCorruptProjectionCensuses(3).every(
                (projection) =>
                    projection.hiddenLowSubsetCount === 1 &&
                    projection.hiddenTerminalSubsetCount === 0 &&
                    projection.hiddenDirectedPairwiseMasterCount === 49 &&
                    projection.honestSourceCount === 7 &&
                    projection.corruptSourceCount === 3 &&
                    projection.hiddenHonestSourceBitCount === 280 &&
                    projection.extractableCorruptSourceBitCount === 120,
            ),
        ).toBe(true);
    });

    it('enumerates the exact matched-mask span for every corrupt triple', () => {
        const corruptTriples = completionSubsets(3);
        expect(corruptTriples).toHaveLength(120);
        let productDifferenceCount = 0;
        for (const [tripleOrdinal, corruptSubset] of corruptTriples.entries()) {
            const corruptParticipants = Array.from(
                { length: participantCount },
                (_, position) => position,
            ).filter((position) => (corruptSubset & (1 << position)) !== 0);
            const { normalizedVanishingPolynomial, wordKeys } =
                enumerateMatchedMaskHiddenSpan(corruptParticipants);
            expect(normalizedVanishingPolynomial).toHaveLength(4);
            expect(normalizedVanishingPolynomial[0]).toBe(1);
            expect(wordKeys.size).toBe(8_192);
            for (const corruptPosition of corruptParticipants) {
                expect(
                    evaluateFieldPolynomial(
                        normalizedVanishingPolynomial,
                        corruptPosition + 1,
                    ),
                ).toBe(0);
            }

            for (let sample = 0; sample < 5; sample += 1) {
                const firstZero = [
                    0,
                    (tripleOrdinal + sample + 1) & 0x0f,
                    (3 * tripleOrdinal + sample + 5) & 0x0f,
                    (tripleOrdinal + 7 * sample + 9) & 0x0f,
                ];
                const secondZero = [
                    0,
                    (5 * tripleOrdinal + sample + 2) & 0x0f,
                    (tripleOrdinal + 3 * sample + 6) & 0x0f,
                    (7 * tripleOrdinal + sample + 10) & 0x0f,
                ];
                const firstOne = addFieldPolynomials(
                    firstZero,
                    normalizedVanishingPolynomial,
                );
                const secondOne = addFieldPolynomials(
                    secondZero,
                    normalizedVanishingPolynomial,
                );
                for (const corruptPosition of corruptParticipants) {
                    const coordinate = corruptPosition + 1;
                    expect(evaluateFieldPolynomial(firstZero, coordinate)).toBe(
                        evaluateFieldPolynomial(firstOne, coordinate),
                    );
                    expect(
                        evaluateFieldPolynomial(secondZero, coordinate),
                    ).toBe(evaluateFieldPolynomial(secondOne, coordinate));
                }
                const products = [
                    multiplyFieldPolynomials(firstZero, secondZero),
                    multiplyFieldPolynomials(firstOne, secondZero),
                    multiplyFieldPolynomials(firstZero, secondOne),
                    multiplyFieldPolynomials(firstOne, secondOne),
                ];
                for (const product of products.slice(1)) {
                    const difference = addFieldPolynomials(
                        products[0],
                        product,
                    );
                    expect(wordKeys.has(matchedMaskWordKey(difference))).toBe(
                        true,
                    );
                    productDifferenceCount += 1;
                }
            }
        }
        expect(productDifferenceCount).toBe(1_800);
    });
});
